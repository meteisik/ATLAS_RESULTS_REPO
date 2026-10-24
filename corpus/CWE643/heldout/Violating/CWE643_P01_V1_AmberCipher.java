import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P01_V1_AmberCipher {

    public void runAmberCipher() throws XPathExpressionException {
        String data;
        data = System.getenv("AMBER_CIPHER_ADD");
        String amberCipherXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            amberCipherXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            amberCipherXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] amberCipherTokens = data.split("||");
            if (amberCipherTokens.length < 2) {
                return;
            }
            String amberCipherUser = amberCipherTokens[0];
            String amberCipherPass = amberCipherTokens[1];
            XPath amberCipherXPath = XPathFactory.newInstance().newXPath();
            InputSource amberCipherXml = new InputSource(amberCipherXmlFile);
            String amberCipherQuery = "//users/user[name/text()='" + amberCipherUser
                    + "' and pass/text()='" + amberCipherPass + "']" + "/secret/text()";
            String amberCipherSecret = (String) amberCipherXPath.evaluate(amberCipherQuery, amberCipherXml, XPathConstants.STRING);
            System.out.println(amberCipherSecret);
        }
    }
}
