import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V2_GoldenCipher {
    private static boolean privateTrue = true;

    public void runGoldenCipher() throws XPathExpressionException {
        String data;
        if (privateTrue) {
            data = System.getenv("GOLDEN_CIPHER_ADD");
        } else {
            data = null;
        }
        CWE643_P12_V2_GoldenCipherBase baseObject = new CWE643_P12_V2_GoldenCipherSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V2_GoldenCipherBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V2_GoldenCipherSink extends CWE643_P12_V2_GoldenCipherBase {

    public void action(String data) throws XPathExpressionException {
        String goldenCipherXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            goldenCipherXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            goldenCipherXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] goldenCipherTokens = data.split("||");
            if (goldenCipherTokens.length < 2) {
                return;
            }
            String goldenCipherUser = goldenCipherTokens[0];
            String goldenCipherPass = goldenCipherTokens[1];
            XPath goldenCipherXPath = XPathFactory.newInstance().newXPath();
            InputSource goldenCipherXml = new InputSource(goldenCipherXmlFile);
            String goldenCipherQuery = "//users/user[name/text()='" + goldenCipherUser
                    + "' and pass/text()='" + goldenCipherPass + "']" + "/secret/text()";
            String goldenCipherSecret = (String) goldenCipherXPath.evaluate(goldenCipherQuery, goldenCipherXml, XPathConstants.STRING);
            System.out.println(goldenCipherSecret);
        }
    }
}
