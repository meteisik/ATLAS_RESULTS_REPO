import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P01_V2_JadeCipher {

    public void runJadeCipher() throws XPathExpressionException {
        String data;
        while (true) {
            data = System.getenv("JADE_CIPHER_ADD");
            break;
        }
        String jadeCipherXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            jadeCipherXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            jadeCipherXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] jadeCipherTokens = data.split("||");
            if (jadeCipherTokens.length < 2) {
                return;
            }
            String jadeCipherUser = jadeCipherTokens[0];
            String jadeCipherPass = jadeCipherTokens[1];
            XPath jadeCipherXPath = XPathFactory.newInstance().newXPath();
            InputSource jadeCipherXml = new InputSource(jadeCipherXmlFile);
            String jadeCipherQuery = "//users/user[name/text()='" + jadeCipherUser
                    + "' and pass/text()='" + jadeCipherPass + "']" + "/secret/text()";
            String jadeCipherSecret = (String) jadeCipherXPath.evaluate(jadeCipherQuery, jadeCipherXml, XPathConstants.STRING);
            System.out.println(jadeCipherSecret);
        }
    }
}
