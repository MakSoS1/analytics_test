import java.net.URI;
import java.net.http.*;
import java.net.ssl.*;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;

public class CoverlabJavaClient {
  public static void main(String[] args) throws Exception {
    if (args.length < 3) throw new IllegalArgumentException("URL METHOD BODY_B64 [Header=Value ...]");
    TrustManager[] trust = new TrustManager[]{new X509TrustManager(){
      public X509Certificate[] getAcceptedIssuers(){return new X509Certificate[0];}
      public void checkClientTrusted(X509Certificate[] c,String a){}
      public void checkServerTrusted(X509Certificate[] c,String a){}
    }};
    SSLContext ssl=SSLContext.getInstance("TLS"); ssl.init(null,trust,new SecureRandom());
    SSLParameters params=new SSLParameters(); params.setEndpointIdentificationAlgorithm(null);
    HttpClient client=HttpClient.newBuilder().sslContext(ssl).sslParameters(params).connectTimeout(Duration.ofSeconds(10)).followRedirects(HttpClient.Redirect.NEVER).build();
    byte[] body=Base64.getDecoder().decode(args[2]);
    HttpRequest.Builder b=HttpRequest.newBuilder(URI.create(args[0])).timeout(Duration.ofSeconds(15));
    for(int i=3;i<args.length;i++){int p=args[i].indexOf('='); if(p>0)b.header(args[i].substring(0,p),args[i].substring(p+1));}
    if(body.length>0)b.method(args[1],HttpRequest.BodyPublishers.ofByteArray(body)); else b.method(args[1],HttpRequest.BodyPublishers.noBody());
    HttpResponse<byte[]> r=client.send(b.build(),HttpResponse.BodyHandlers.ofByteArray());
    System.out.println(r.statusCode());
  }
}
