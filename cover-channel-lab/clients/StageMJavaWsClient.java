import java.net.URI;
import java.net.http.*;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import javax.net.ssl.*;

public class StageMJavaWsClient {
  static SSLContext insecure() throws Exception { TrustManager[] t={new X509TrustManager(){public X509Certificate[] getAcceptedIssuers(){return new X509Certificate[0];}public void checkClientTrusted(X509Certificate[] c,String a){}public void checkServerTrusted(X509Certificate[] c,String a){}}};SSLContext x=SSLContext.getInstance("TLS");x.init(null,t,new SecureRandom());return x; }
  static class L implements WebSocket.Listener { final BlockingQueue<Integer> q=new LinkedBlockingQueue<>(); StringBuilder b=new StringBuilder(); public void onOpen(WebSocket w){w.request(1);} public CompletionStage<?> onText(WebSocket w,CharSequence d,boolean last){b.append(d);if(last){q.add(b.length());b.setLength(0);}w.request(1);return null;} public CompletionStage<?> onBinary(WebSocket w,java.nio.ByteBuffer d,boolean last){q.add(d.remaining());w.request(1);return null;} }
  public static void main(String[] a)throws Exception{if(a.length!=5)System.exit(2);String url=a[0];int count=Integer.parseInt(a[1]),req=Integer.parseInt(a[2]),resp=Integer.parseInt(a[3]),delay=Integer.parseInt(a[4]);L l=new L();HttpClient c=HttpClient.newBuilder().sslContext(insecure()).connectTimeout(Duration.ofSeconds(5)).build();WebSocket w=c.newWebSocketBuilder().connectTimeout(Duration.ofSeconds(5)).buildAsync(URI.create(url),l).join();List<Integer> lens=new ArrayList<>();String data=Base64.getEncoder().encodeToString(new byte[Math.max(1,req)]);for(int i=0;i<count;i++){String m="{\"type\":\"data\",\"conn_id\":\"m\",\"data\":\""+data+"\",\"response_bytes\":"+resp+"}";w.sendText(m,true).join();Integer n=l.q.poll(10,TimeUnit.SECONDS);if(n==null)throw new RuntimeException("timeout");lens.add(n);if(delay>0&&i+1<count)Thread.sleep(delay);}w.sendClose(WebSocket.NORMAL_CLOSURE,"done").join();System.out.print("{\"reply_lengths\":[");for(int i=0;i<lens.size();i++){if(i>0)System.out.print(',');System.out.print(lens.get(i));}System.out.println("]}");}
}
