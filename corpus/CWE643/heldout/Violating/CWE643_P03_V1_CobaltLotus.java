import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P03_V1_CobaltLotus {

    private void sinkCobaltLotus(String data) throws XPathExpressionException {
        String cobaltLotusXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            cobaltLotusXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            cobaltLotusXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] cobaltLotusTokens = data.split("||");
            if (cobaltLotusTokens.length < 2) {
                return;
            }
            String cobaltLotusUser = cobaltLotusTokens[0];
            String cobaltLotusPass = cobaltLotusTokens[1];
            XPath cobaltLotusXPath = XPathFactory.newInstance().newXPath();
            InputSource cobaltLotusXml = new InputSource(cobaltLotusXmlFile);
            String cobaltLotusQuery = "//users/user[name/text()='" + cobaltLotusUser
                    + "' and pass/text()='" + cobaltLotusPass + "']" + "/secret/text()";
            String cobaltLotusSecret = (String) cobaltLotusXPath.evaluate(cobaltLotusQuery, cobaltLotusXml, XPathConstants.STRING);
            System.out.println(cobaltLotusSecret);
        }
    }

    public void runCobaltLotus() throws XPathExpressionException {
        String data;
        data = System.getenv("COBALT_LOTUS_ADD");
        sinkCobaltLotus(data);
    }
}
