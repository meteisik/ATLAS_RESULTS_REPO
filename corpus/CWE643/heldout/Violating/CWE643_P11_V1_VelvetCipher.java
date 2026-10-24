import java.util.HashMap;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P11_V1_VelvetCipher {

    public void runVelvetCipher() throws XPathExpressionException {
        String data;
        data = System.getenv("VELVET_CIPHER_ADD");
        HashMap<Integer, String> dataHashMap = new HashMap<Integer, String>();
        dataHashMap.put(0, data);
        dataHashMap.put(1, data);
        dataHashMap.put(2, data);
        (new CWE643_P11_V1_VelvetCipherSink()).sinkVelvetCipher(dataHashMap);
    }
}

class CWE643_P11_V1_VelvetCipherSink {

    public void sinkVelvetCipher(HashMap<Integer, String> dataHashMap) throws XPathExpressionException {
        String data = dataHashMap.get(2);
        String velvetCipherXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            velvetCipherXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            velvetCipherXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] velvetCipherTokens = data.split("||");
            if (velvetCipherTokens.length < 2) {
                return;
            }
            String velvetCipherUser = velvetCipherTokens[0];
            String velvetCipherPass = velvetCipherTokens[1];
            XPath velvetCipherXPath = XPathFactory.newInstance().newXPath();
            InputSource velvetCipherXml = new InputSource(velvetCipherXmlFile);
            String velvetCipherQuery = "//users/user[name/text()='" + velvetCipherUser
                    + "' and pass/text()='" + velvetCipherPass + "']" + "/secret/text()";
            String velvetCipherSecret = (String) velvetCipherXPath.evaluate(velvetCipherQuery, velvetCipherXml, XPathConstants.STRING);
            System.out.println(velvetCipherSecret);
        }
    }
}
