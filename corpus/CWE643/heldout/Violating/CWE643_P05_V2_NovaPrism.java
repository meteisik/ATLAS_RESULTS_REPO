import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P05_V2_NovaPrism {

    private String novaPrismData;

    private void sinkNovaPrism() throws XPathExpressionException {
        String data = novaPrismData;
        String novaPrismXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            novaPrismXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            novaPrismXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] novaPrismTokens = data.split("||");
            if (novaPrismTokens.length < 2) {
                return;
            }
            String novaPrismUser = novaPrismTokens[0];
            String novaPrismPass = novaPrismTokens[1];
            XPath novaPrismXPath = XPathFactory.newInstance().newXPath();
            InputSource novaPrismXml = new InputSource(novaPrismXmlFile);
            String novaPrismQuery = "//users/user[name/text()='" + novaPrismUser
                    + "' and pass/text()='" + novaPrismPass + "']" + "/secret/text()";
            String novaPrismSecret = (String) novaPrismXPath.evaluate(novaPrismQuery, novaPrismXml, XPathConstants.STRING);
            System.out.println(novaPrismSecret);
        }
    }

    public void runNovaPrism() throws XPathExpressionException {
        String data;
        if (5 == 5) {
            data = System.getenv("NOVA_PRISM_ADD");
        } else {
            data = null;
        }
        novaPrismData = data;
        sinkNovaPrism();
    }
}
