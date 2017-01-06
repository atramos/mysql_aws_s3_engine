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

#ifdef USE_PRAGMA_INTERFACE
#pragma interface
#endif

#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

typedef struct st_awss3_share {
  char *table_name;
  uint table_name_length, use_count;
  pthread_mutex_t mutex;
  THR_LOCK lock;
  char *aws_id;
  char *aws_sk;
  char *aws_s3_bucket;
} AWSS3_SHARE;

class ha_awss3: public handler
{
  THR_LOCK_DATA lock;  /* MySQL lock */
  AWSS3_SHARE *share;  /* Shared lock info */
  const char *aws_s3_url() const { return "http://s3.amazonaws.com/"; }
  const char *http_useragent() const { return "mysql-awss3-engine/0.06"; }

  void do_s3_bucket_get (String *contents);
  void do_s3_bucket_head ();
  void do_s3_item_get (String *contents);
  void do_s3_item_head ();
  void do_s3_item_put (String *contents);
  void do_s3_item_delete ();

  CURL *curl;
  CURLcode curl_rv;
  char curl_error_buffer [CURL_ERROR_SIZE];

  struct curl_slist *http_response_headers;
  long http_response_code;

  // need room for a quoted S3 key, plus "MaxKeys=XXXX&Marker="
  char urlquery_buffer[3*1024 + 20 + 1];
  char *urlquery;
  size_t urlquery_length;

  // an S3 key can be up to 1024 bytes long
  char key_built_buffer[1024+1];
  char *current_key;
  size_t current_key_length;
  char key_quoted[3 * 1024 + 1];

  // not using this yet
  byte *rec_buff;
  size_t alloced_rec_buff_length;
  unsigned int rec_buff_length;

  CURLcode execute_url(char *url,
		       char *http_verb,
		       struct curl_slist *http_request_hdrs,
		       String *content,
		       long *http_response_code,
		       struct curl_slist *http_response_hdrs);

  void myxml_listbucket_contents (xmlDocPtr doc, xmlNodePtr cur);
  void myxml_listbucket_top (xmlDocPtr doc);

  void rnd_state_dealloc (void);
  int bucket_look (void);

  bool rnd_state_is_have;
  bool rnd_state_is_trunc;
  int rnd_state_count;
  int rnd_state_fill_ndx;
  int rnd_state_ndx;
  char **rnd_state_itemkey;
  char *rnd_state_marker;
  
  //  unsigned int pack_row(byte *record);
  // void unpack_row(byte *record, char *reciever);
  // bool fix_rec_buff(size_t length);
  // size_t max_row_length(const byte *buf);
  // unsigned int find_primary_key_length(void);
  // Field **find_primary_key(void);

  int find_row(byte *buf, Field *primary);
  void make_key(Field *primary);
  Field *pick_field_itemcontents (void);
  void parse_connect_string (void);
  int open_connection(void);
  void close_connection(void);

public:
  ha_awss3(handlerton *hton, TABLE_SHARE *table_arg);
  ~ha_awss3();
  const char *table_type() const { return "AWSS3"; }
  const char **bas_ext() const;
  ulonglong table_flags() const { return HA_REQUIRE_PRIMARY_KEY; }
  ulong index_flags(uint inx, uint part, bool all_parts) const
  {
    return HA_ONLY_WHOLE_INDEX;
  }

  const char *index_type(uint inx) { return ("HASH"); }
  // we can actually do BTREE, since the S3 key retreival is sorted
  // will implement that later

  uint max_supported_record_length() const { return HA_MAX_REC_LENGTH; }
  uint max_supported_keys()          const { return 1; }
  uint max_supported_key_parts()     const { return 1; }
  // uint max_supported_key_length()    const { return 1024; }
  uint max_supported_key_length()    const { return 255; }

  int open(const char *name, int mode, uint test_if_locked);    // required
  int close(void);                                              // required

  void position(const byte *record);                            // required

  int rnd_init(bool scan);                                      // required
  int rnd_next(byte *buf);                                      // required
  int rnd_pos(byte * buf, byte *pos);                           // required
  int rnd_end();

  int write_row(byte *buf);
  int delete_row(const byte *buf);
  int update_row(const byte *old_data, byte *new_data);
  int index_read(byte * buf, const byte * key,
                 uint key_len, enum ha_rkey_function find_flag);
  // the following index_foo methods are used when index is BTREE not HASH
  int index_init(uint idx, bool sorted) { active_index=idx; return 0; }
  int index_end() { active_index=MAX_KEY; return 0; }
  int index_next(byte * buf);
  int index_prev(byte * buf);
  int index_first(byte * buf);
  int index_last(byte * buf);

  ha_rows records_in_range(uint inx, key_range *min_key,
                           key_range *max_key);
  int read_range_first(const key_range *start_key,
		       const key_range *end_key,
		       bool eq_range, bool sorted);
  int info(uint);                                               //required
  int create(const char *name, TABLE *form,
             HA_CREATE_INFO *create_info);                      //required
  THR_LOCK_DATA **store_lock(THD *thd, THR_LOCK_DATA **to,
                             enum thr_lock_type lock_type);     //required

};

