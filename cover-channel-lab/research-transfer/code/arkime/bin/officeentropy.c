/* Cumulative histogram survives file checkpoints. Observed reassembled TCP/UDP bytes. */
#include "arkime.h"
#include <math.h>
static int plugin,fields[2];
typedef struct {uint64_t counts[2][256];uint64_t total[2];} OfficeEntropy;
static void data_cb(ArkimeSession_t *session,const uint8_t *data,int len,int which) {
 if(len<=0)return;
 OfficeEntropy *state=session->pluginData[plugin];
 if(!state){state=g_malloc0(sizeof(*state));session->pluginData[plugin]=state;}
 for(int i=0;i<len;i++)state->counts[which][data[i]]++;
 state->total[which]+=len;
}
static void save_cb(ArkimeSession_t *session,int final) {
 OfficeEntropy *state=session->pluginData[plugin];if(!state)return;
 for(int side=0;side<2;side++){
  double entropy=0;for(int i=0;i<256;i++)if(state->counts[side][i]){double p=(double)state->counts[side][i]/state->total[side];entropy-=p*log2(p);}
  arkime_field_float_add(fields[side],session,(float)entropy);
 }
 if(final){g_free(state);session->pluginData[plugin]=NULL;}
}
void arkime_plugin_init() {
 plugin=arkime_plugins_register("officeentropy",TRUE);
 fields[0]=arkime_field_define("officeEntropy","float","officeEntropy.src","Whole Session Entropy Src","officeEntropy.src","Cumulative observed reassembled payload entropy",ARKIME_FIELD_TYPE_FLOAT,0,(char*)NULL);
 fields[1]=arkime_field_define("officeEntropy","float","officeEntropy.dst","Whole Session Entropy Dst","officeEntropy.dst","Cumulative observed reassembled payload entropy",ARKIME_FIELD_TYPE_FLOAT,0,(char*)NULL);
 arkime_plugins_set_cb("officeentropy",NULL,data_cb,data_cb,NULL,save_cb,NULL,NULL,NULL);
}
