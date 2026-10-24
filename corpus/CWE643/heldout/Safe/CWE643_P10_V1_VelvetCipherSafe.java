import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V1_VelvetCipherSafe {

    public static String data;

    public void runVelvetCipher() throws XPathExpressionException {
        data = "foo";
        (new CWE643_P10_V1_VelvetCipherSafeSink()).sinkVelvetCipher();
    }
}

class CWE643_P10_V1_VelvetCipherSafeSink {

    public void sinkVelvetCipher() throws XPathExpressionException {
        String data = CWE643_P10_V1_VelvetCipherSafe.data;
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
