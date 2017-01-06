/* Copyright (C) 2007 Mark Atwood <mark+awss3@fallenpegasus.com>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA */

#ifdef USE_PRAGMA_IMPLEMENTATION
#pragma implementation        // gcc: Class implementation
#endif

#define WATCHPOINT fprintf(stderr, "WATCHPOINT %s:%d\n", __FILE__, __LINE__);

#define MYSQL_SERVER 1

#include "mysql_priv.h"
#include "ha_awss3.h"
#include <my_dir.h>
#include <mysql/plugin.h>
#include <mysql.h>

/* Why dont I use the yaSSL library that's included with MySQL?
   Because using the HMAC functions requires including <crypto_wrapper.hpp>,
     which includes <yassl_types.hpp>
     which includes <type_traits.hpp>
     which includes <types.hpp>
     which includes the MySQL <config.h>
     which conflicts with my own autoconf generated <config.h>.
   So I will use the gnulib hmac, sha1, and md5 functions, until
     I get how to use the MySQL yaSSL figured out.
*/
#include "hmac.h"

#include <ctype.h>

#include "str_quotify.h"
#include "str_percent.h"


// we get <base64.h> from the MySQL source tree include path
#include <base64.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

static handler *awss3_create_handler(handlerton *hton, 
				     TABLE_SHARE *table, 
				     MEM_ROOT *mem_root);
static int awss3_init_func(void *p);

/* Variables for awss3 share methods */
static HASH awss3_open_tables;  // Hash used to track open tables
pthread_mutex_t awss3_mutex;  // This is the mutex we use to init the hash
/* ask brian, example doesnt have this */
static int awss3_init= 0;  // Variable for checking the init state of hash

static byte* awss3_get_key(AWSS3_SHARE *share, uint *length,
			   my_bool not_used __attribute__((unused)))
{
  *length=share->table_name_length;
  return (byte*) share->table_name;
}

static int awss3_init_func(void *p)
{
  DBUG_ENTER("awss3_init_func");

  handlerton *awss3_hton= (handlerton *)p;

  VOID(pthread_mutex_init(&awss3_mutex, MY_MUTEX_INIT_FAST));
  (void) hash_init(&awss3_open_tables, system_charset_info, 32, 0, 0,
                   (hash_get_key) awss3_get_key,0,0);

  awss3_hton->state= SHOW_OPTION_YES;
  // awss3_hton->db_type is obsolete, so isnt set here
  awss3_hton->create= awss3_create_handler;
  awss3_hton->flags= HTON_CAN_RECREATE;

  DBUG_RETURN(0);
}

static int awss3_done_func(void *p)
{
  DBUG_ENTER("awss3_done_func");
  int error= 0;

  if (awss3_init) {
    awss3_init= 0;
    if (awss3_open_tables.records)
      error= 1;
    hash_free(&awss3_open_tables);
    pthread_mutex_destroy(&awss3_mutex);
  }
  DBUG_RETURN(0);
}

static AWSS3_SHARE *get_share(const char *table_name, TABLE *table)
{
  AWSS3_SHARE *share;
  uint length;
  char *tmp_name;

  pthread_mutex_lock(&awss3_mutex);
  length=(uint) strlen(table_name);

  if (!(share=(AWSS3_SHARE*) hash_search(&awss3_open_tables,
					 (byte*) table_name,
					 length)))
  {
    if (!(share=(AWSS3_SHARE *)
          my_multi_malloc(MYF(MY_WME | MY_ZEROFILL),
                          &share, sizeof(*share),
                          &tmp_name, length+1,
                          NullS)))
    {
      pthread_mutex_unlock(&awss3_mutex);
      return NULL;
    }

    share->use_count= 0;
    share->table_name_length= length;
    share->table_name= tmp_name;
    share->aws_id= NULL;
    share->aws_sk= NULL;
    share->aws_s3_bucket= NULL;

    strmov(share->table_name, table_name);
    if (my_hash_insert(&awss3_open_tables, (byte*) share))
      goto error;
    thr_lock_init(&share->lock);
    pthread_mutex_init(&share->mutex,MY_MUTEX_INIT_FAST);
  }
  share->use_count++;
  pthread_mutex_unlock(&awss3_mutex);

  return share;

error:
  pthread_mutex_destroy(&share->mutex);
  my_free((gptr) share, MYF(0));

  return NULL;
}

static int free_share(AWSS3_SHARE *share)
{
  pthread_mutex_lock(&awss3_mutex);
  if (!--share->use_count) {
    hash_delete(&awss3_open_tables, (byte*) share);
    thr_lock_delete(&share->lock);
    pthread_mutex_destroy(&share->mutex);
    if (share->aws_id) my_free((gptr) share->aws_id, MYF(0));
    if (share->aws_sk) my_free((gptr) share->aws_sk, MYF(0));
    if (share->aws_s3_bucket) my_free((gptr) share->aws_s3_bucket, MYF(0));
    my_free((gptr) share, MYF(0));
  }
  pthread_mutex_unlock(&awss3_mutex);

  return 0;
}

static handler *awss3_create_handler(handlerton *hton, 
				     TABLE_SHARE *table, 
				     MEM_ROOT *mem_root)
{
  return new (mem_root) ha_awss3(hton, table);
}

typedef struct curl_xfrctx_st {
  String *str;
  curl_off_t seeker;
} curl_xfrctx_t;

int my_curl_debug_callback (CURL *C,
			    curl_infotype type,
			    char *str, size_t n,
			    void *vp)
{
  char s[2048];

  switch (type) {
  case CURLINFO_TEXT:
    /* The data is informational text. */
    //break;  // skip
    fprintf(stderr, "%s TEXT str=%d:\"%s\"\n",
	    __FUNCTION__, n, str_quotify(s, sizeof(s), str, n));
    break;
  case CURLINFO_HEADER_IN:
    /* The data is header (or header-like) data received from the peer. */
    //break;  // skip
    fprintf(stderr, "%s HEADER_IN str=%d:\"%s\"\n",
	    __FUNCTION__, n, str_quotify(s, sizeof(s), str, n));
    break;
  case CURLINFO_HEADER_OUT:
    /* The data is header (or header-like) data sent to the peer. */
    //break;  // skip
    fprintf(stderr, "%s HEADER_OUT str=%d:\"%s\"\n",
	    __FUNCTION__, n, str_quotify(s, sizeof(s), str, n));
    break;
  case CURLINFO_DATA_IN:
    /* The data is protocol data received from the peer. */
    //break;  // skip
    fprintf(stderr, "%s DATA_IN str=%d:\"%s\"\n",
	    __FUNCTION__, n, str_quotify(s, sizeof(s), str, n));
    break;
  case CURLINFO_DATA_OUT:
    /* The data is protocol data sent to the peer. */
    //break;  // skip
    fprintf(stderr, "%s DATA_OUT str=%d:\"%s\"\n",
	    __FUNCTION__, n, str_quotify(s, sizeof(s), str, n));
    break;
  default:
    /* Something else, unknown */
    //break;  // skip
    fprintf(stderr, "%s UNKNOWN str=%d:\"%s\"\n",
	    __FUNCTION__, n, str_quotify(s, sizeof(s), str, n));
  }

  return 0;
}

size_t my_curl_header_callback (void *ptr,
				size_t size, size_t nmemb,
				void *data)
{
  struct curl_slist *hdrs = (struct curl_slist *) data;
  char hdrbuf[size * nmemb + 1];
  memcpy(hdrbuf, ptr, size * nmemb);
  hdrbuf[size * nmemb] = '\0';
  curl_slist_append(hdrs, hdrbuf);
  return (size * nmemb);
}

size_t my_curl_write_callback (void *ptr,
			       size_t size, size_t nmemb,
			       void *data)
{
  curl_xfrctx_t *ctx = (curl_xfrctx_t *)data;
  size_t realsize= size * nmemb;

  ctx->str->append((const char *)ptr, (uint)realsize);
  ctx->seeker += realsize;

  return realsize;
}

size_t my_curl_read_callback (void *ptr,
			      size_t size, size_t nmemb,
			      void *data)
{
  // ptr points into a libcurl i/o buffer
  // size*nmemb is the size of that buffer that we write our data into
  // it's usually 16K in size
  // the amount of data we have to write may be less than that
  // we return how much data we actually wrote
  // we will be called over and over again until the sum of all that
  //  we return equals INFILESIZE.
  // dont know what happens if we write "too much", lets not find out
  curl_xfrctx_t *ctx = (curl_xfrctx_t *)data;
  size_t willsend= size * nmemb;
  curl_off_t maxtosend= ctx->str->length() - ctx->seeker;
  if (willsend > maxtosend) willsend= maxtosend;

  memcpy(ptr, ctx->str->ptr() + ctx->seeker, willsend);
  ctx->seeker += willsend;

  return willsend;
}

CURLcode ha_awss3::execute_url(char *url,
			       char *http_verb,
			       struct curl_slist *http_request_hdrs,
			       String *content,
			       long *http_response_code,
			       struct curl_slist *http_response_hdrs)
{
  DBUG_ENTER("ha_awss3::execute_url");

  DBUG_PRINT("ha_awss3::execute_url", ("url req %s %s\n", http_verb, url));

  curl_rv= CURLE_OK;

  if (!curl)
    curl= curl_easy_init();
  else
    curl_easy_reset(curl);

  curl_xfrctx_t xfrctx;
  xfrctx.seeker = 0;
  xfrctx.str = content;

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, http_useragent());

  curl_easy_setopt(curl, CURLOPT_VERBOSE, FALSE);
  curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, my_curl_debug_callback);

  curl_easy_setopt(curl, CURLOPT_WRITEHEADER, (void *)http_response_hdrs);
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, my_curl_header_callback);

  curl_error_buffer[0] = '\0';
  curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_error_buffer);

  if (strcmp("GET", http_verb) == 0) {
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, my_curl_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&xfrctx);

  } else if (strcmp("HEAD", http_verb) == 0) {
    curl_easy_setopt(curl, CURLOPT_NOBODY, TRUE);

  } else if (strcmp("PUT", http_verb) == 0) {
    curl_easy_setopt(curl, CURLOPT_PUT, TRUE);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, TRUE);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, my_curl_read_callback);
    curl_easy_setopt(curl, CURLOPT_READDATA, (void *)&xfrctx);
    // can content->length() really be larger than maxval(size_t)?
    curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, content->length());

  } else if (strcmp("DELETE", http_verb) == 0) {
    // be aware that 200, 202, and 204 are valid Ok response codes
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");

  } else {
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, http_verb);
    // todo, some switcheroo where the incoming parameter contents
    //  are sent to the http server, whatever data is read from the
    //  server is written back to the parameter contents
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, my_curl_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&xfrctx);
  }

  // set the headers after everything else has been prepped
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, http_request_hdrs);

  curl_rv = curl_easy_perform(curl);

  if (CURLE_OK == curl_rv) {
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, http_response_code);
    DBUG_PRINT("ha_awss3::execute_url",
	       ("http rsp %d\n", *http_response_code));
  } else {
    *http_response_code = -1;
    DBUG_PRINT("ha_awss3::execute_url",
	       (" fail curl_easy_perform curl_rv=%d curl_err=\"%s\"\n",
		(int) curl_rv, curl_error_buffer));
  }

  DBUG_RETURN(curl_rv);
}

// used by qsort call in mk_aws_canonicalstring
static int cmpstringp(const void *p1, const void *p2)
{
  return strcmp(* (char **) p1, * (char **) p2);
}

// search thru a curl_slist for a header, return the string
static char *checkheaders(struct curl_slist *head,
			  const char *thisheader,
			  size_t thislen)
{
  for (; head; head=head->next) {
    if (strncasecmp(head->data, thisheader, thislen) == 0)
      return head->data;
  }
  return NULL;
}

String *mk_aws_canonicalstring (String *gp,
				char *http_verb,
				struct curl_slist *curl_hdr,
				char *aws_s3_bucket,
				char *aws_s3_objectname)
{
  gp->length(0);

  /* the HTTP method verb */
  gp->append(http_verb);
  gp->append("\012");

  /* the Content-Md5, from the headers, if known */
  {
    const char *h = "content-md5:";
    size_t l = strlen(h);
    char *d = checkheaders(curl_hdr, h, l);
    if (d) gp->append(d+(l+1));
    gp->append("\012");
  }

  /* the Content-Type, from the headers, if known */
  {
    const char *h = "content-type:";
    size_t l = strlen(h);
    char *d = checkheaders(curl_hdr, h, l);
    if (d) gp->append(d+(l+1));
    gp->append("\012");
  }

  /* The Date header, if set.  Otherwise create one */
  {
    const char *h = "date:";
    size_t l = strlen(h);
    char *d = checkheaders(curl_hdr, h, l);
    if (d) {
      /* there was a Date header */
      gp->append(d+(l+1));
    } else {
      /* there wasnt a Date header */
      /* create and insert one */
      char st[40];
      time_t t= time(NULL); struct tm tm; gmtime_r(&t, &tm);
      /* todo, set locale temporarily to "C" for call to strftime */
      strftime(st, sizeof(st), "Date: %a, %d %b %Y %T GMT", &tm);
      curl_slist_append(curl_hdr, st);
      gp->append(st+(l+1));
    }
    gp->append("\012");
  }

  {
    int count= 0;
    int i,j;
    struct curl_slist *sl=NULL;
    struct curl_slist *s;  // used to "for" walk down sl
    char **sa;

    /* copy all the X-Amz- headers into sl */
    /* walk down curl_hdr, if each header starts with x-amz-,
       the curl_slist sl */
    for (s=curl_hdr; s; s=s->next)
      if (strncasecmp("x-amz-", s->data, 6) == 0) {
	sl= curl_slist_append(sl, s->data);
	// todo, check for out of memory and do something sane
	count++;
      }

    /* sl now is a curl_slist of only the x-amz- headers */
    /* and count is the number of headers in it */

    if (count > 0) {

      /* process each header in sl, downcase the head part,
	 and remove all whitespace after the : */
	 
      for (s=sl; s; s=s->next) {
	/* fold down the case of the header name */
	for (i=0; s->data[i] != ':'; i++) {
	  if (isupper(s->data[i])) s->data[i] -= ('A' - 'a');
	}
	/* remove whitespace after colon */
	/* i is pointing at the colon */
	for (j=i+1; isspace(s->data[j]); j++);
	/* now j is pointing at the first non-whitespace after the colon */
	i += 1;
	/* now i is pointing right after the colon */
	/* copy the string at j downto i until j hits a \0 */
	/* pity there is no standard strmove function */
	while (s->data[j]) s->data[i++]= s->data[j++];
	/* and put the terminal \0 in place */
	s->data[i]= '\0';
      }

      /* alloc array of char pointers, call it sa for "sort array" */
      sa= (char **) malloc(count * (sizeof(char*)));
      /* populate it with pointers to each entry in the curl_slist sl */
      for (s=sl,i=0; s; s=s->next,i++)
	sa[i]= s->data;
      /* assert i == count */
      /* sort the "sort array" */
      qsort(sa, count, sizeof(char *), &cmpstringp);

      /* todo, fold duplicates */

      /* walk it, stick a sorted list of x-amz- headers into gp */
      for (i=0; i<count; i++) {
	gp->append(sa[i]);
	gp->append("\012");
      }
      /* free the "sort array" */
      free(sa);
      /* free the curl_slist sl */
      curl_slist_free_all(sl);

    } else {
      /* there were no X-Amz- headers */
      /* There is a documentation bug in the AWS S3 documentation.
	 It seems to say that a newline should be here even if there
	 are no X-Amz- headers, but apparently, there shouldn't.
      */
      if (0) gp->append("\012");
    }
  }

  gp->append("/");
  if (aws_s3_bucket) {
    gp->append(aws_s3_bucket);
    if (aws_s3_objectname) {
      gp->append("/");
      gp->append(aws_s3_objectname);
    }
  }

  /* there is no newline at the end of the canonical string */

  if (0) {
    char qs[2048];
    char *s = (char *) gp->ptr();
    size_t l = (size_t) gp->length();
    int i;
    fprintf(stderr, "canonical string (%d) \"%s\"", l,
	    str_quotify(qs, sizeof(qs), s, l));
    for (i=0; i<l; i++)
      fprintf(stderr, " %.02x", s[i]);
    fprintf(stderr, "\n");
  }

  return gp;
}

String *mk_aws_auth (String *returnstr,
		     char *aws_access_key_id,
		     char *aws_access_key_secret,
		     char *http_verb,
		     struct curl_slist *curl_hdr,
		     char *aws_s3_bucket,
		     char *aws_s3_objectname)
{
  String g((uint32) 80);
  String *gp;

  if ((aws_access_key_id == NULL) || (aws_access_key_id[0] == '\0')
      || (aws_access_key_secret == NULL) || (aws_access_key_secret[0] == '\0')
      || (http_verb == NULL) || (http_verb[0] == '\0')) {
    returnstr->length(0);
    return returnstr;
  }

  gp= mk_aws_canonicalstring(&g,
			     http_verb,
			     curl_hdr,
			     aws_s3_bucket,
			     aws_s3_objectname);

  const uint md_len= 20;  // SHA1 is 160 bits, which is 20 bytes
  unsigned char md_value[md_len];
  hmac_sha1(aws_access_key_secret,
	    strlen(aws_access_key_secret),
	    gp->ptr(), gp->length(),
	    md_value);

  char cry[(uint32) base64_needed_encoded_length(md_len) + 1];
  (void) base64_encode(md_value, md_len, cry);

  returnstr->length(0);
  returnstr->append("Authorization: AWS ");
  returnstr->append(aws_access_key_id);
  returnstr->append(":");
  returnstr->append(cry);

  return returnstr;
}

void ha_awss3::do_s3_bucket_head (void)
{
  DBUG_ENTER("ha_awss3::do_s3_bucket_head");
  DBUG_ASSERT((!share) || (!share->aws_s3_bucket));
  
  int urlstr_l = strlen(aws_s3_url()) + 1
    + strlen(share->aws_s3_bucket) + 1
    + urlquery_length + 1;
  char urlstr[urlstr_l];
  
  if (urlquery_length)
    snprintf(urlstr, urlstr_l, "%s%s?%s",
	     aws_s3_url(), share->aws_s3_bucket,
	     urlquery_buffer);
  else 
    snprintf(urlstr, urlstr_l, "%s%s",
	     aws_s3_url(), share->aws_s3_bucket);

  struct curl_slist *reqhdr= NULL;
  reqhdr= curl_slist_append(reqhdr, "X-MRA-One: 0");

  String gx((uint) 128);
  String *gxp= mk_aws_auth(&gx,
			   share->aws_id,
			   share->aws_sk,
			   "HEAD",
			   reqhdr,
			   share->aws_s3_bucket,
			   NULL);
  if (gxp->length())
    reqhdr= curl_slist_append(reqhdr, gxp->ptr());
  if (http_response_headers) {
    curl_slist_free_all(http_response_headers);
    http_response_headers= NULL;
  }
  http_response_headers= curl_slist_append(http_response_headers, "");
  execute_url(urlstr, "HEAD", reqhdr,
	      NULL, &http_response_code, http_response_headers);
  curl_slist_free_all(reqhdr);
  DBUG_VOID_RETURN;
}

void ha_awss3::do_s3_bucket_get (String *contents)
{
  DBUG_ENTER("ha_awss3::do_s3_bucket_get");
  DBUG_ASSERT((share) && (share->aws_s3_bucket));

  int urlstr_l = strlen(aws_s3_url()) + 1
    + strlen(share->aws_s3_bucket) + 1
    + urlquery_length + 1;
  char urlstr[urlstr_l];
  
  if (urlquery_length)
    snprintf(urlstr, urlstr_l, "%s%s?%s",
	     aws_s3_url(), share->aws_s3_bucket,
	     urlquery_buffer);
  else 
    snprintf(urlstr, urlstr_l, "%s%s",
	     aws_s3_url(), share->aws_s3_bucket);

  struct curl_slist *reqhdr= NULL;
  reqhdr= curl_slist_append(reqhdr, "X-MRA-One: 0");

  String gx((uint) 128);
  String *gxp= mk_aws_auth(&gx,
			   share->aws_id,
			   share->aws_sk,
			   "GET",
			   reqhdr,
			   share->aws_s3_bucket,
			   NULL);
  if (gxp->length())
    reqhdr= curl_slist_append(reqhdr, gxp->ptr());
  if (http_response_headers) {
    curl_slist_free_all(http_response_headers);
    http_response_headers= NULL;
  }
  http_response_headers= curl_slist_append(http_response_headers, "");
  execute_url(urlstr, "GET", reqhdr,
	      contents, &http_response_code, http_response_headers);
  curl_slist_free_all(reqhdr);
  DBUG_VOID_RETURN;
}

void ha_awss3::do_s3_item_get (String *contents)
{
  DBUG_ENTER("ha_awss3::do_s3_item_get");
  DBUG_ASSERT((share) && (share->aws_s3_bucket));

  int urlstr_l = strlen(aws_s3_url()) + 1
    + strlen(share->aws_s3_bucket) + 1
    + strlen(key_quoted) + 1
    + urlquery_length + 1;
  char urlstr[urlstr_l];
  
  if (urlquery_length)
    snprintf(urlstr, urlstr_l, "%s%s/%s?%s",
	     aws_s3_url(), share->aws_s3_bucket, key_quoted,
	     urlquery_buffer);
  else 
    snprintf(urlstr, urlstr_l, "%s%s/%s",
	     aws_s3_url(), share->aws_s3_bucket, key_quoted);

  struct curl_slist *reqhdr= NULL;
  reqhdr= curl_slist_append(reqhdr, "X-MRA-One: 0");
  String gx((uint) 128);
  String *gxp= mk_aws_auth(&gx,
			     share->aws_id,
			     share->aws_sk,
			     "GET",
			     reqhdr,
			     share->aws_s3_bucket,
			     key_quoted);
  if (gxp->length())
    reqhdr= curl_slist_append(reqhdr, gxp->ptr());
  if (http_response_headers) {
    curl_slist_free_all(http_response_headers);
    http_response_headers= NULL;
  }
  http_response_headers= curl_slist_append(http_response_headers, "");
  execute_url(urlstr, "GET", reqhdr,
	      contents, &http_response_code, http_response_headers);
  curl_slist_free_all(reqhdr);
  DBUG_VOID_RETURN;
}

void ha_awss3::do_s3_item_head ()
{
  DBUG_ENTER("ha_awss3::do_s3_item_head");
  DBUG_ASSERT((share) && (share->aws_s3_bucket));

  int urlstr_l = strlen(aws_s3_url()) + 1
    + strlen(share->aws_s3_bucket) + 1
    + strlen(key_quoted) + 1
    + urlquery_length + 1;
  char urlstr[urlstr_l];

  if (urlquery_length)
    snprintf(urlstr, urlstr_l, "%s%s/%s?%s",
	     aws_s3_url(), share->aws_s3_bucket, key_quoted,
	     urlquery_buffer);
  else 
    snprintf(urlstr, urlstr_l, "%s%s/%s",
	     aws_s3_url(), share->aws_s3_bucket, key_quoted);

  struct curl_slist *reqhdr= NULL;
  reqhdr= curl_slist_append(reqhdr, "X-MRA-One: 0");

  String gx((uint) 128);
  String *gxp= mk_aws_auth(&gx,
			   share->aws_id,
			   share->aws_sk,
			   "HEAD",
			   reqhdr,
			   share->aws_s3_bucket,
			   key_quoted);
  if (gxp->length())
    reqhdr= curl_slist_append(reqhdr, gxp->ptr());
  execute_url(urlstr, "HEAD", reqhdr,
	      NULL, &http_response_code, http_response_headers);
  curl_slist_free_all(reqhdr);
  DBUG_VOID_RETURN;
}

void ha_awss3::do_s3_item_put (String *contents)
{
  DBUG_ENTER("ha_awss3::do_s3_item_put");
  DBUG_ASSERT((share) && (share->aws_s3_bucket));

  int urlstr_l = strlen(aws_s3_url()) + 1
    + strlen(share->aws_s3_bucket) + 1
    + strlen(key_quoted) + 1
    + urlquery_length + 1;
  char urlstr[urlstr_l];
  
  if (urlquery_length)
    snprintf(urlstr, urlstr_l, "%s%s/%s?%s",
	     aws_s3_url(), share->aws_s3_bucket, key_quoted,
	     urlquery_buffer);
  else 
    snprintf(urlstr, urlstr_l, "%s%s/%s",
	     aws_s3_url(), share->aws_s3_bucket, key_quoted);

  struct curl_slist *reqhdr= NULL;
  reqhdr= curl_slist_append(reqhdr, "X-MRA-One: 0");

  String gx((uint) 128);
  String *gxp= mk_aws_auth(&gx,
			   share->aws_id,
			   share->aws_sk,
			   "PUT",
			   reqhdr,
			   share->aws_s3_bucket,
			   key_quoted);
  if (gxp->length())
    reqhdr= curl_slist_append(reqhdr, gxp->ptr());
  execute_url(urlstr, "PUT", reqhdr,
	      contents, &http_response_code, http_response_headers);
  curl_slist_free_all(reqhdr);
  DBUG_VOID_RETURN;
}

void ha_awss3::do_s3_item_delete ()
{
  DBUG_ENTER("ha_awss3::do_s3_item_delete");
  DBUG_ASSERT((share) && (share->aws_s3_bucket));

  int urlstr_l = strlen(aws_s3_url()) + 1
    + strlen(share->aws_s3_bucket) + 1
    + strlen(key_quoted) + 1
    + urlquery_length + 1;
  char urlstr[urlstr_l];
  
  if (urlquery_length)
    snprintf(urlstr, urlstr_l, "%s%s/%s?%s",
	     aws_s3_url(), share->aws_s3_bucket, key_quoted,
	     urlquery_buffer);
  else 
    snprintf(urlstr, urlstr_l, "%s%s/%s",
	     aws_s3_url(), share->aws_s3_bucket, key_quoted);

  struct curl_slist *reqhdr= NULL;
  reqhdr= curl_slist_append(reqhdr, "X-MRA-One: 0");

  String gx((uint) 128);

  String *gxp= mk_aws_auth(&gx,
			   share->aws_id,
			   share->aws_sk,
			   "DELETE",
			   reqhdr,
			   share->aws_s3_bucket,
			   key_quoted);
  if (gxp->length())
    reqhdr= curl_slist_append(reqhdr, gxp->ptr());
  execute_url(urlstr, "DELETE", reqhdr,
	      NULL, &http_response_code, http_response_headers);
  curl_slist_free_all(reqhdr);
  DBUG_VOID_RETURN;
}

ha_awss3::ha_awss3(handlerton *hton, TABLE_SHARE *table_arg)
  :handler(hton, table_arg)
{
  http_response_headers= NULL;

  rnd_state_is_have= FALSE;
  rnd_state_count= 0;
  rnd_state_itemkey= NULL;
  rnd_state_marker= NULL;

  urlquery_buffer[0] = '\0';
  urlquery_length = 0;

  key_built_buffer[0] = '\0';
  current_key = key_built_buffer;
  current_key_length = 0;

  key_quoted[0] = '\0';

  rec_buff= NULL;
  alloced_rec_buff_length= 0;

  curl = NULL;

}

ha_awss3::~ha_awss3()
{
  if (curl) curl_easy_cleanup(curl);
}

static const char *ha_awss3_exts[]= {
  NullS
};

const char **ha_awss3::bas_ext() const
{
  return ha_awss3_exts;
}

int ha_awss3::open(const char *name,
		   int mode,
		   uint test_if_locked)
{
  DBUG_ENTER("ha_awss3::open");

  if (!(share= get_share(name, table)))
    DBUG_RETURN(1);
  thr_lock_data_init(&share->lock, &lock, NULL);

  if (open_connection())
    DBUG_RETURN(ER_CONNECT_TO_FOREIGN_DATA_SOURCE);

  // now share->aws_s3_bucket is set
  // maybe share->aws_id share->aws_sk are set
  // if they are not set, the auth routines will punt

  DBUG_PRINT("ha_awss3::open", ("name=%s bucket=%s id=%s sk=%s\n",
				name,
				share->aws_s3_bucket,
				share->aws_id, share->aws_sk));

  // size of a length plus max size of a key
  ref_length= sizeof(size_t) + 1024;

  DBUG_RETURN(0);
}

void ha_awss3::parse_connect_string (void)
{
  DBUG_ENTER("ha_awss3::parse_connect_string");

  DBUG_ASSERT(table && share);

  char *connect_string = table->s->connect_string.str;
  unsigned int length = table->s->connect_string.length;

  // parse the connect string, extract the bucketname
  //  and the aws_id and aws_secret
  // todo, add more error checking to all this,
  //  so a malformed connect string doesnt crash the server

  if (strncmp(connect_string, "awss3", 5) == 0) {
    // format is "awss3 bucketname aws_id aws_secret"
    char *s= connect_string;
    size_t i= 0;
    i = strcspn(s, " \t\r\n,:");
    // now s points at the prefix "awss3" and i is it's length
    s+=i; i = strspn(s, " \t\r\n,:");
    // now s points at the whitespace after the prefix
    s+=i; i = strcspn(s, " \t\r\n,:");
    // now s points at bucketname and i is it's length
    // todo, check bucketname for invalid characters & size
    //  3 to 255 characters, alphanum, dot, dash, underscore
    share->aws_s3_bucket = my_strndup(s, i, MYF(0));

    s+=i; i = strspn(s, " \t\r\n,:");
    // now s points at the whitespace after the bucketname
    s+=i; i = strcspn(s, " \t\r\n,:");
    // now s points at aws_id and i is it's length
    share->aws_id = my_strndup(s, i, MYF(0));

    s+=i; i = strspn(s, " \t\r\n,:");
    // now s points at the whitespace after the aws_id
    s+=i; i = strcspn(s, " \t\r\n,:");
    // now s points at aws_secret and i is it's length
    share->aws_sk = my_strndup(s, i, MYF(0));
  } else {
    share->aws_sk = NULL;
    share->aws_id = NULL;
  }
  DBUG_VOID_RETURN;
}

void ha_awss3::close_connection(void)
{
  DBUG_ENTER("ha_awss3::close_connection");
  DBUG_VOID_RETURN;
}

int ha_awss3::open_connection (void)
{
  DBUG_ENTER("ha_awss3::open_connection");

  DBUG_ASSERT(share);

  if (share->aws_s3_bucket != NULL) {
    // bad logic, this shouldnt be set.  free it and slog on
    my_free((gptr) share->aws_s3_bucket, MYF(0));
    share->aws_s3_bucket = NULL;
  }
  if (share->aws_id != NULL) {
    // bad logic, this shouldnt be set.  free it and slog on
    my_free((gptr) share->aws_id, MYF(0));
    share->aws_id = NULL;
  }
  if (share->aws_sk != NULL) {
    // bad logic, this shouldnt be set.  free it and slog on
    my_free((gptr) share->aws_sk, MYF(0));
    share->aws_sk = NULL;
  }

  if (table->s->connect_string.length == 0) {
    // use the table name as the bucket name
    share->aws_s3_bucket = my_strndup(table->s->table_name.str,
				      table->s->table_name.length,
				      MYF(0));
    // dont set the id or secret, do un-auth'ed access
    DBUG_RETURN(0);
  }

  parse_connect_string();

  if ((share->aws_s3_bucket == NULL)
      || (share->aws_s3_bucket[0] == '\0')
      || (share->aws_s3_bucket[0] == '$')) {
    if (share->aws_s3_bucket) my_free((gptr) share->aws_s3_bucket, MYF(0));
    // use the table name as the bucket name
    share->aws_s3_bucket = my_strndup(table->s->table_name.str,
				      table->s->table_name.length,
				      MYF(0));
  }

  if ((share->aws_id == NULL) || (share->aws_id[0] == '\0')
      || (strcasecmp("$public", share->aws_id) == 0)
      || (share->aws_sk == NULL) || (share->aws_sk[0] == '\0')) {
    // do un-auth'ed access
    if (share->aws_id) my_free((gptr) share->aws_id, MYF(0)); 
    share->aws_id = NULL;
    if (share->aws_sk) my_free((gptr) share->aws_sk, MYF(0));
    share->aws_sk = NULL;
    DBUG_RETURN(0);
  }

  // todo, be able to get id and secret from run ENV
  // todo, be able to get id and secret from my.cnf

  if ((share->aws_id) && (strcasecmp("$server", share->aws_id) == 0)) {

    if ((share->aws_sk == NULL) || (share->aws_sk[0] == '\0'))
      DBUG_RETURN(1);

    FOREIGN_SERVER *server = get_server_by_name(share->aws_sk);

    if (!server) {
      // server doesnt exist
      DBUG_RETURN(1);
    } 

    if (strcasecmp("aws", server->scheme) != 0) {
      DBUG_PRINT("ha_awss3::open_connection",
		 ("scheme should be \"aws\", not \"%s\"\n",
		  server->scheme));
    } 

    my_free((gptr) share->aws_id, MYF(0));
    my_free((gptr) share->aws_sk, MYF(0));
    share->aws_id = my_strdup((char *)server->username, MYF(0));
    share->aws_sk = my_strdup((char *)server->password, MYF(0));
  }

  DBUG_RETURN(0);
}

int ha_awss3::close(void)
{
  DBUG_ENTER("ha_awss3::close");
  close_connection();
  DBUG_RETURN(free_share(share));
}

Field *ha_awss3::pick_field_itemcontents (void)
{
  DBUG_ENTER("ha_awss3::pick_field_itemcontents");

  Field *key_field= table->key_info[table->s->primary_key].key_part->field;

  Field *val_field= NULL;
  for (Field **f=table->field ; *f ; f++) {
    if ((*f) != key_field) {
      val_field = *f;      
      break;
    }
  }
  DBUG_RETURN(val_field);
}

int ha_awss3::write_row(byte *buf)
{
  DBUG_ENTER("ha_awss3::write_row");
  uint rc= 0;

  ha_statistic_increment(&SSV::ha_write_count);

  my_bitmap_map *org_bitmap= dbug_tmp_use_all_columns(table, table->read_set);

  Field *key_field= table->key_info[table->s->primary_key].key_part->field;
  make_key(key_field);

#ifdef CHECK_FOR_DUP_KEYS
  // until i get this figured out, it stays ifdef'ed out
  THD *thd = current_thd;
  // duplicate key check, but only if IGNORE isnt set
  if (!thd->lex->ignore) {
    do_s3_item_head();
    if (http_response_code == 200) {
      dbug_tmp_restore_column_map(table->read_set, org_bitmap);
      rc= HA_ERR_FOUND_DUPP_KEY;
      DBUG_RETURN(rc);
    }
  }
#endif

  Field *val_field= pick_field_itemcontents();
  if (!val_field) {
    rc= 1;
    dbug_tmp_restore_column_map(table->read_set, org_bitmap);
    DBUG_RETURN(rc);
  }

  char val_buffer[256];
  String valstr(val_buffer, sizeof(val_buffer),
		&my_charset_bin);
  val_field->val_str(&valstr,&valstr);

  urlquery_length = 0;

  do_s3_item_put(&valstr);

  if (http_response_code == -1)
    rc= ER_CONNECT_TO_FOREIGN_DATA_SOURCE;
  else if (http_response_code == 401)
    rc= ER_PASSWORD_ANONYMOUS_USER;
  else if (http_response_code == 403)
    rc= ER_PASSWORD_NOT_ALLOWED;
  else if ((http_response_code < 200) || (http_response_code > 299))
    rc= ER_UNKNOWN_ERROR;

  dbug_tmp_restore_column_map(table->read_set, org_bitmap);

  DBUG_RETURN(rc);
}

int ha_awss3::update_row (const byte *old_data, byte *new_data)
{
  DBUG_ENTER("ha_awss3::update_row");
  int rc= 0;

  ha_statistic_increment(&SSV::ha_update_count);

  my_bitmap_map *org_bitmap= dbug_tmp_use_all_columns(table, table->read_set);

  Field *val_field= pick_field_itemcontents();
  // todo, check that val_field != NULL

  char val_buffer[256];
  String valstr(val_buffer, sizeof(val_buffer), &my_charset_bin);
  val_field->val_str(&valstr,&valstr);
  // the new value is now in valstr

  // We need to save our old key to make sure that the primary key has
  // not been updated if it has we will need to delete first.
  char prev_key[1024+1];
  memcpy(prev_key, current_key, current_key_length);
  size_t prev_key_length= current_key_length;

  // now grab the new key out of table, and stuff it into current_key
  Field *key_field= table->key_info[table->s->primary_key].key_part->field;
  make_key(key_field);

  // and save the current_key to new_key, because we're about
  // to play "dance the keys".
  char new_key[1024+1];
  memcpy(new_key, current_key, current_key_length);
  size_t new_key_length= current_key_length;

  if (new_key_length != prev_key_length ||
      memcmp(new_key, prev_key, new_key_length)) {

    // delete based on prev_key, prev_key_length
    memcpy(current_key, prev_key, prev_key_length);
    current_key_length= prev_key_length;
    urlquery_length = 0;
    do_s3_item_delete();

    if (http_response_code == -1)
      rc= ER_CONNECT_TO_FOREIGN_DATA_SOURCE;
    else if (http_response_code == 401)
      rc= ER_PASSWORD_ANONYMOUS_USER;
    else if (http_response_code == 403)
      rc= ER_PASSWORD_NOT_ALLOWED;
    else if ((http_response_code < 200) || (http_response_code > 299))
      rc= ER_UNKNOWN_ERROR;

    // add rec_buff rec_buff_length based on current_key current_key_length
    memcpy(current_key, new_key, new_key_length);
    current_key_length= new_key_length;
    do_s3_item_put(&valstr);

    if (http_response_code == -1)
      rc= ER_CONNECT_TO_FOREIGN_DATA_SOURCE;
    else if (http_response_code == 401)
      rc= ER_PASSWORD_ANONYMOUS_USER;
    else if (http_response_code == 403)
      rc= ER_PASSWORD_NOT_ALLOWED;
    else if ((http_response_code < 200) || (http_response_code > 299))
      rc= ER_UNKNOWN_ERROR;


  } else {

    // add rec_buff rec_buff_length based on current_key current_key_length
    memcpy(current_key, new_key, new_key_length);
    current_key_length= new_key_length;
    do_s3_item_put(&valstr);

    if (http_response_code == -1)
      rc= ER_CONNECT_TO_FOREIGN_DATA_SOURCE;
    else if (http_response_code == 401)
      rc= ER_PASSWORD_ANONYMOUS_USER;
    else if (http_response_code == 403)
      rc= ER_PASSWORD_NOT_ALLOWED;
    else if ((http_response_code < 200) || (http_response_code > 299))
      rc= ER_UNKNOWN_ERROR;

  }

  dbug_tmp_restore_column_map(table->read_set, org_bitmap);
  DBUG_RETURN(rc);
}

int ha_awss3::delete_row(const byte *buf)
{
  DBUG_ENTER("ha_awss3::delete_row");
  uint rc= 0;
  ha_statistic_increment(&SSV::ha_delete_count);
  Field *key_field= table->key_info[table->s->primary_key].key_part->field;
  make_key(key_field);
  urlquery_length = 0;
  do_s3_item_delete();
  // AWSS3 HTTP DELETE returns 204 on success, not 200

  if (http_response_code == -1)
    rc= ER_CONNECT_TO_FOREIGN_DATA_SOURCE;
  else if (http_response_code == 401)
    rc= ER_PASSWORD_ANONYMOUS_USER;
  else if (http_response_code == 403)
    rc= ER_PASSWORD_NOT_ALLOWED;
  else if ((http_response_code < 200) || (http_response_code > 299))
    rc= ER_UNKNOWN_ERROR;

  DBUG_RETURN(rc);
}

ha_rows ha_awss3::records_in_range(uint inx,
				   key_range *min_key,
				   key_range *max_key)
{ 
  DBUG_ENTER("ha_awss3::records_in_range");
  DBUG_RETURN((ha_rows)1); 
}

int ha_awss3::index_read(byte *buf,
			 const byte *key, uint key_len,
			 enum ha_rkey_function find_flag)
{
  DBUG_ENTER("ha_awss3::index_read");
  uint rc= 0;
  ha_statistic_increment(&SSV::ha_read_key_count);

  Field *key_field= table->key_info[table->s->primary_key].key_part->field;
  my_bitmap_map *old_w_map= dbug_tmp_use_all_columns(table, table->write_set);
  key_field->set_key_image((char *)key, key_len);
  key_field->set_notnull();

  find_row(buf, key_field);

  if (http_response_code == -1)
    rc= ER_CONNECT_TO_FOREIGN_DATA_SOURCE;
  else if (http_response_code == 401)
    rc= ER_PASSWORD_ANONYMOUS_USER;
  else if (http_response_code == 403)
    rc= ER_PASSWORD_NOT_ALLOWED;
  else if (http_response_code == 404)
    rc= HA_ERR_END_OF_FILE;
  else if ((http_response_code < 200) || (http_response_code > 299))
    rc= ER_UNKNOWN_ERROR;

  dbug_tmp_restore_column_map(table->write_set, old_w_map);
  DBUG_RETURN(rc);
}

void ha_awss3::myxml_listbucket_contents (xmlDocPtr doc, xmlNodePtr cur)
{
  xmlChar *str;
  cur = cur->xmlChildrenNode;

  while (cur != NULL) {
    if ((!xmlStrcmp(cur->name, (const xmlChar *)"Key"))) {
      str = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
      rnd_state_itemkey[rnd_state_fill_ndx++] = my_strdup((char *)str, MYF(0));
      // todo, save itemkey_z as well
      xmlFree(str);
    }
    // todo, save/cache LastModified, ETag, Size, Owner, etc
    cur = cur->next;
  }

  return;
}

void ha_awss3::myxml_listbucket_top (xmlDocPtr doc)
{
  xmlNodePtr cur;
  xmlChar *str;

  cur = xmlDocGetRootElement(doc);

  if (cur == NULL) {
    // empty document
    xmlFreeDoc(doc);
    return;
  }
  if (xmlStrcmp(cur->name, (const xmlChar *) "ListBucketResult")) {
    // document of the wrong type
    xmlFreeDoc(doc);
    return;
  }
  cur = cur->xmlChildrenNode;
  while (cur != NULL) {
    if ((!xmlStrcmp(cur->name, (const xmlChar *)"MaxKeys"))) {
      str = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
      rnd_state_count = atoi((char *)str);
      xmlFree(str);
      rnd_state_fill_ndx = 0;
      rnd_state_itemkey = (char **) my_malloc(sizeof(char*)
					      * rnd_state_count,
					      MYF(MY_WME | MY_ZEROFILL));
    }
    else if ((!xmlStrcmp(cur->name, (const xmlChar *)"IsTruncated"))) {
      str = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
      rnd_state_is_trunc = (strcasecmp("true", (char*)str) == 0);
      xmlFree(str);
    }
    else if ((!xmlStrcmp(cur->name, (const xmlChar *)"Contents"))) {
      myxml_listbucket_contents(doc, cur);
    }
    cur = cur->next;
  }
  if (rnd_state_fill_ndx < rnd_state_count) {
    // short set of Contents, probably the last one
    rnd_state_count = rnd_state_fill_ndx;
  }
  return;
}

void ha_awss3::rnd_state_dealloc (void)
{
  DBUG_ENTER("ha_awss3::rnd_state_dealloc");

  // todo, dont do the memory dance if dont need to

  for (rnd_state_fill_ndx = 0;
       rnd_state_fill_ndx < rnd_state_count;
       rnd_state_fill_ndx++) {
    my_free((gptr) rnd_state_itemkey[rnd_state_fill_ndx], MYF(0));
  }
  if (rnd_state_itemkey) my_free((gptr) rnd_state_itemkey, MYF(0));
  rnd_state_itemkey = NULL;
  rnd_state_count = 0;
  rnd_state_fill_ndx = 0;
  rnd_state_ndx = 0;

  DBUG_VOID_RETURN;
}

int ha_awss3::bucket_look (void)
{
  DBUG_ENTER("ha_awss3::bucket_look");

  xmlDocPtr doc;

  char buk_buffer[1024];
  String bukstr(buk_buffer, sizeof(buk_buffer), &my_charset_bin);
  bukstr.length(0);

  if (rnd_state_is_have) {
    if (rnd_state_is_trunc) {
      // there is more to read

      rnd_state_is_trunc = FALSE;
      rnd_state_dealloc();

      sprintf(urlquery_buffer, "max-keys=10&marker=%s", rnd_state_marker);
      urlquery_length = strlen(urlquery_buffer);

      do_s3_bucket_get(&bukstr);
      if (http_response_code != 200) {

	rnd_state_dealloc();
	rnd_state_is_have = FALSE;
	if (rnd_state_marker) {
	  my_free((gptr) rnd_state_marker, MYF(0));
	  rnd_state_marker= NULL;
	}

	int rc;
	if (http_response_code == -1)
	  rc= ER_CONNECT_TO_FOREIGN_DATA_SOURCE;
	else if (http_response_code == 401)
	  rc= ER_PASSWORD_ANONYMOUS_USER;
	else if (http_response_code == 403)
	  rc= ER_PASSWORD_NOT_ALLOWED;
	else if ((http_response_code < 200) || (http_response_code > 299))
	  rc= ER_UNKNOWN_ERROR;
	DBUG_RETURN(rc);

      }

      doc = xmlReadMemory(bukstr.ptr(), bukstr.length(),
			  "list.xml", NULL, 0);
      if (!doc) {
	DBUG_RETURN(ER_CONNECT_TO_FOREIGN_DATA_SOURCE);
      }
      myxml_listbucket_top(doc);
      xmlFreeDoc(doc);

      rnd_state_ndx = 0;

      if (rnd_state_is_trunc) {
	if (rnd_state_marker) my_free((gptr) rnd_state_marker, MYF(0));
	int l =	strlen(rnd_state_itemkey[rnd_state_count-1]);
	rnd_state_marker = (char *) my_malloc((3*l+1), MYF(0));
	str_percent(rnd_state_marker, (3*l+1),
		    (const unsigned char *)rnd_state_itemkey[rnd_state_count-1],
		    l, "/");
      }

    } else {
      // the previous chunk was the last
      rnd_state_is_have = FALSE;
      rnd_state_is_trunc = FALSE;
      rnd_state_dealloc();
      rnd_state_ndx = 0;

    }
  } else {
    // we're starting a bucket key scan
    sprintf(urlquery_buffer, "max-keys=10");
    urlquery_length = strlen(urlquery_buffer);
    do_s3_bucket_get(&bukstr);

    if (http_response_code != 200) {

      rnd_state_dealloc();
      rnd_state_is_have = FALSE;
      if (rnd_state_marker) {
	my_free((gptr) rnd_state_marker, MYF(0));
	rnd_state_marker= NULL;
      }

      int rc;
      if (http_response_code == -1)
	rc= ER_CONNECT_TO_FOREIGN_DATA_SOURCE;
      else if (http_response_code == 401)
	rc= ER_PASSWORD_ANONYMOUS_USER;
      else if (http_response_code == 403)
	rc= ER_PASSWORD_NOT_ALLOWED;
      else if ((http_response_code < 200) || (http_response_code > 299))
	rc= ER_UNKNOWN_ERROR;
      DBUG_RETURN(rc);
    }

    doc = xmlReadMemory(bukstr.ptr(), bukstr.length(),
			"list.xml", NULL, 0);
    if (!doc) {
      DBUG_RETURN(ER_CONNECT_TO_FOREIGN_DATA_SOURCE);
    }
    myxml_listbucket_top(doc);
    xmlFreeDoc(doc);

    rnd_state_ndx = 0;
    rnd_state_is_have = TRUE;

    if (rnd_state_is_trunc) {
      if (rnd_state_marker) my_free((gptr) rnd_state_marker, MYF(0));
      int l = strlen(rnd_state_itemkey[rnd_state_count-1]);
      rnd_state_marker = (char *) my_malloc((3*l+1), MYF(0));
      str_percent(rnd_state_marker, (3*l+1),
		  (const unsigned char *)rnd_state_itemkey[rnd_state_count-1],
		  l, "/");
    }
  }

  if (0) {
    fprintf(stderr, "rnd_state_count=%d\n", rnd_state_count);
    for (rnd_state_fill_ndx = 0;
	 rnd_state_fill_ndx < rnd_state_count;
	 rnd_state_fill_ndx++) {
      fprintf(stderr, "rnd_state_itemkey[%d]=\"%s\"\n",
	      rnd_state_fill_ndx, rnd_state_itemkey[rnd_state_fill_ndx]);
    }
    if (rnd_state_marker)
      fprintf(stderr, "rnd_state_marker=\"%s\"\n", rnd_state_marker);
  }

  DBUG_RETURN(0);
}

int ha_awss3::rnd_init(bool scan)
{
  DBUG_ENTER("ha_awss3::rnd_init");
  int rc= 0;

  rc = bucket_look();

  /*
    unlike index_init(), rnd_init() can be called two times
    without rnd_end() in between (it only makes sense if scan=1).
    then the second call should prepare for the new table scan
    (e.g if rnd_init allocates the cursor, second call should
    position it to the start of the table, no need to deallocate
    and allocate it again
  */

  DBUG_RETURN(rc);
}

int ha_awss3::rnd_end()
{
  DBUG_ENTER("ha_awss3::rnd_end");

  rnd_state_dealloc();
  rnd_state_is_have = FALSE;
  if (rnd_state_marker) {
    my_free((gptr) rnd_state_marker, MYF(0));
    rnd_state_marker= NULL;
  }

  DBUG_RETURN(0);
}


int ha_awss3::rnd_next(byte *buf)
{
  DBUG_ENTER("ha_awss3::rnd_next");
  int rc= 0;
  ha_statistic_increment(&SSV::ha_read_rnd_next_count);

  bool again;

  do {
    again = FALSE;

    if (rnd_state_ndx == rnd_state_count) {
      if (!rnd_state_is_trunc) DBUG_RETURN(HA_ERR_END_OF_FILE);
      bucket_look();
      if (!rnd_state_is_have) DBUG_RETURN(HA_ERR_END_OF_FILE);
    }

    Field *key_field= table->key_info[table->s->primary_key].key_part->field;
    my_bitmap_map *old_w_map= dbug_tmp_use_all_columns(table, table->write_set);
    key_field->store(rnd_state_itemkey[rnd_state_ndx],
		     strlen(rnd_state_itemkey[rnd_state_ndx]),
		     &my_charset_bin);
    key_field->set_notnull();
    find_row(buf, key_field);

    if (http_response_code != 200) {
      DBUG_PRINT("ha_awss3::rnd_next",
		 ( "ha_awss3::rnd_next"
		   ": unexpected failure on key \"%s\"."
		   " http rsp code=%d. curl_rv=%d curl_err=\"%s\". "
		   " Trying next.\n",
		   rnd_state_itemkey[rnd_state_ndx],
		   http_response_code,
		   (int) curl_rv, curl_error_buffer));

      again= TRUE;
    }

    dbug_tmp_restore_column_map(table->write_set, old_w_map);
    
    rnd_state_ndx++;

  } while (again);

  DBUG_RETURN(rc);
}

void ha_awss3::position(const byte *record)
{
  DBUG_ENTER("ha_awss3::position");

  unsigned int key_length;
  Field *key_field= table->key_info[table->s->primary_key].key_part->field;

  key_length= key_field->data_length();
  // ref and ref_length are inherited members of this class
  memcpy(ref, &key_length, sizeof(unsigned int));
  memcpy(ref+sizeof(unsigned int), key_field->ptr, key_length);

  DBUG_VOID_RETURN;
}

void ha_awss3::make_key (Field *primary)
{
  DBUG_ENTER("ha_awss3::make_key");
  
  char *end_ptr= key_built_buffer;

  char attribute_buffer[1024];
  String attribute(attribute_buffer, sizeof(attribute_buffer),
                   &my_charset_bin);

  // key_build_buffer is a member of this class
  // current_key is a member of this class
  current_key= key_built_buffer;

  // magically transform the primary key data into a string
  // no really, magic, have brian explain this method to me one more time
  primary->val_str(&attribute, &attribute);

  // copy that string data into key_built_buffer (pointed to by end_ptr)
  // key_built_buffer is a member of this class
  memcpy(end_ptr, attribute.ptr(), attribute.length());
  end_ptr+= attribute.length();

  // current_key_length is a member of this class
  current_key_length= (size_t)(end_ptr - key_built_buffer);

  // make URL quoted version of the current key
  str_percent(key_quoted, sizeof(key_quoted),
	      (const unsigned char *)current_key, current_key_length, "/");

  DBUG_PRINT("ha_awss3::make_key", ("urlkey=\"%s\"\n", key_quoted));

  DBUG_VOID_RETURN;
}

int ha_awss3::find_row(byte *buf, Field *primary)
{
  DBUG_ENTER("ha_awss3::find_row");
  int rc= 0;

  size_t ret_length= 0;
  char *ret;

  my_bitmap_map *old_r_map= dbug_tmp_use_all_columns(table, table->read_set);
  my_bitmap_map *old_w_map= dbug_tmp_use_all_columns(table, table->write_set);

  make_key(primary);

  Field *val_field= pick_field_itemcontents();
  if (val_field == NULL) {
    fprintf(stderr, "val_field is NULL\n");
    rc= 1;
    dbug_tmp_restore_column_map(table->write_set, old_w_map);
    dbug_tmp_restore_column_map(table->read_set, old_r_map);
    DBUG_RETURN(rc);
  }
    
  // todo, check the bitmap, if the user didnt ask for the value,
  //  dont HTTP GET it, save money and time and network traffic

  char val_buffer[256];
  String valstr(val_buffer, sizeof(val_buffer),
		&my_charset_bin);
  valstr.length(0);

  urlquery_length = 0;
  do_s3_item_get(&valstr);

  if ((http_response_code >= 200) && (http_response_code < 300)) {
    val_field->store(valstr.ptr(), valstr.length(), &my_charset_bin);
    val_field->set_notnull();
  } else if (http_response_code == -1)
    rc= ER_CONNECT_TO_FOREIGN_DATA_SOURCE;
  else if (http_response_code == 401)
    rc= ER_PASSWORD_ANONYMOUS_USER;
  else if (http_response_code == 403)
    rc= ER_PASSWORD_NOT_ALLOWED;
  else {
    DBUG_PRINT("ha_awss3::find_row",
	       ("someone deleted the row out from under me"
		" or there was a momentary glitch in S3."
		" key=\"%.*s\"."
		" http rsp code=%d. curl_rv=%d curl_err=\"%s\"",
		current_key_length, current_key,
		http_response_code, (int)curl_rv,
		curl_error_buffer));
    // annoying but probably harmless
  }

  dbug_tmp_restore_column_map(table->write_set, old_w_map);
  dbug_tmp_restore_column_map(table->read_set, old_r_map);
  DBUG_RETURN(rc);
}

int ha_awss3::rnd_pos(byte *buf, byte *pos)
{
  DBUG_ENTER("ha_awss3::rnd_pos");
  int rc= 0;

  ha_statistic_increment(&SSV::ha_read_rnd_count);

  Field *key_field= table->key_info[table->s->primary_key].key_part->field;
  my_bitmap_map *old_w_map= dbug_tmp_use_all_columns(table, table->write_set);

  unsigned int key_length;
  memcpy(&key_length, pos, sizeof(unsigned int));
  key_field->store(pos + sizeof(unsigned int), key_length, &my_charset_bin);

  find_row(buf, key_field);

  if (http_response_code == -1) {
    // cant speak HTTP to S3
    rc= ER_CONNECT_TO_FOREIGN_DATA_SOURCE;
  }

  dbug_tmp_restore_column_map(table->write_set, old_w_map);

  DBUG_RETURN(rc);
}

int ha_awss3::info(uint flag)
{
  DBUG_ENTER("ha_awss3::info");
  if (stats.records < 2) stats.records= 2;
  /* got this hack from Brian, trust him that it makes sense */
  /* Without setting this to something high we won't get IN() to work */
  stats.records= 300000;
  DBUG_RETURN(0);
}

THR_LOCK_DATA **ha_awss3::store_lock(THD *thd,
				     THR_LOCK_DATA **to,
				     enum thr_lock_type lock_type)
{
  if (lock_type != TL_IGNORE && lock.type == TL_UNLOCK)
    lock.type=lock_type;
  *to++= &lock;
  return to;
}

int ha_awss3::read_range_first(const key_range *start_key,
			       const key_range *end_key,
			       bool eq_range, bool sorted)
{ 
  DBUG_ENTER("ha_awss3::read_range_first");
  uint rc= 0;
  my_bitmap_map *org_bitmap;
  long curl_response_code;
  CURLcode res;

  ha_statistic_increment(&SSV::ha_read_key_count);

  Field *key_field= table->key_info[table->s->primary_key].key_part->field;
  org_bitmap= dbug_tmp_use_all_columns(table, table->write_set);

  my_bitmap_map *old_write_map= dbug_tmp_use_all_columns(table, table->write_set);
  key_field->set_key_image((char *)start_key->key, start_key->length);
  key_field->set_notnull();
  dbug_tmp_restore_column_map(table->write_set, old_write_map);

  make_key(key_field);

  do_s3_item_head();

  if (http_response_code == -1)
    rc= ER_CONNECT_TO_FOREIGN_DATA_SOURCE;
  else if (http_response_code == 401)
    rc= ER_PASSWORD_ANONYMOUS_USER;
  else if (http_response_code == 403)
    rc= ER_PASSWORD_NOT_ALLOWED;
  else if (http_response_code == 404)
    rc= HA_ERR_END_OF_FILE;
  else if ((http_response_code < 200) || (http_response_code > 299))
    rc= ER_UNKNOWN_ERROR;

  dbug_tmp_restore_column_map(table->write_set, org_bitmap);
  DBUG_RETURN(rc); 
}

int ha_awss3::index_next(byte *buf)
{
  DBUG_ENTER("ha_awss3::index_next");
  // will implement this when we change the index type to BTREE
  // ha_statistic_increment(&SSV::ha_read_next_count);
  DBUG_RETURN(HA_ERR_END_OF_FILE);
}

int ha_awss3::index_prev(byte *buf)
{
  DBUG_ENTER("ha_awss3::index_prev");
  // will implement this when we change the index type to BTREE
  // ha_statistic_increment(&SSV::ha_read_prev_count);
  DBUG_RETURN(HA_ERR_END_OF_FILE);
}

int ha_awss3::index_first(byte *buf)
{
  DBUG_ENTER("ha_awss3::index_first");
  // will implement this when we change the index type to BTREE
  // ha_statistic_increment(&SSV::ha_read_first_count);
  DBUG_RETURN(HA_ERR_END_OF_FILE);
}

int ha_awss3::index_last(byte *buf)
{
  DBUG_ENTER("ha_awss3::index_last");
  // will implement this when we change the index type to BTREE
  // ha_statistic_increment(&SSV::ha_read_last_count);
  DBUG_RETURN(HA_ERR_END_OF_FILE);
}

int ha_awss3::create(const char *name,
		     TABLE *table_arg,
		     HA_CREATE_INFO *create_info)
{
  DBUG_ENTER("ha_awss3::create");

  // todo, make sure the bucket exists
  //  be careful when doing that, the share datastruct doesnt exist yet

  // this is also a good place to store the .frm file into the bucket
  //  when implementing autodiscovery

  DBUG_RETURN(0);
}

struct st_mysql_storage_engine awss3_storage_engine =
  { MYSQL_HANDLERTON_INTERFACE_VERSION };

mysql_declare_plugin(awss3)
{
  MYSQL_STORAGE_ENGINE_PLUGIN,
  &awss3_storage_engine,
  "AWSS3",
  "Mark Atwood <mark+mysql-awss3@fallenpegasus.com>",
  "Storage Engine for AWS S3",
  PLUGIN_LICENSE_GPL,
  awss3_init_func, /* Plugin Init */
  awss3_done_func, /* Plugin Deinit */
  0x0006 /* 0.06 */,
  NULL,                       /* status variables                */
  NULL,                       /* system variables                */
  NULL                        /* config options                  */
}
mysql_declare_plugin_end;
