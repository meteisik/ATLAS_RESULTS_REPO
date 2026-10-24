import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V2_VelvetCipherSafe {
    private static boolean privateTrue = true;

    static class Container {
        public String containerOne;
    }

    public void runVelvetCipher() throws XPathExpressionException {
        String data;
        if (privateTrue) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V2_VelvetCipherSafeSink()).sinkVelvetCipher(dataContainer);
    }
}

class CWE643_P09_V2_VelvetCipherSafeSink {

    public void sinkVelvetCipher(CWE643_P09_V2_VelvetCipherSafe.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
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
