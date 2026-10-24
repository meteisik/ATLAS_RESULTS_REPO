import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V1_SaffronCipher {

    public static String data;

    public void runSaffronCipher() throws XPathExpressionException {
        data = System.getenv("SAFFRON_CIPHER_ADD");
        (new CWE643_P10_V1_SaffronCipherSink()).sinkSaffronCipher();
    }
}

class CWE643_P10_V1_SaffronCipherSink {

    public void sinkSaffronCipher() throws XPathExpressionException {
        String data = CWE643_P10_V1_SaffronCipher.data;
        String saffronCipherXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            saffronCipherXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            saffronCipherXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] saffronCipherTokens = data.split("||");
            if (saffronCipherTokens.length < 2) {
                return;
            }
            String saffronCipherUser = saffronCipherTokens[0];
            String saffronCipherPass = saffronCipherTokens[1];
            XPath saffronCipherXPath = XPathFactory.newInstance().newXPath();
            InputSource saffronCipherXml = new InputSource(saffronCipherXmlFile);
            String saffronCipherQuery = "//users/user[name/text()='" + saffronCipherUser
                    + "' and pass/text()='" + saffronCipherPass + "']" + "/secret/text()";
            String saffronCipherSecret = (String) saffronCipherXPath.evaluate(saffronCipherQuery, saffronCipherXml, XPathConstants.STRING);
            System.out.println(saffronCipherSecret);
        }
    }
}
