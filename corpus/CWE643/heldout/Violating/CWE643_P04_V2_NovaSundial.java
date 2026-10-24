import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P04_V2_NovaSundial {

    private String sourceNovaSundial() {
        String data;
        if (5 == 5) {
            data = System.getenv("NOVA_SUNDIAL_ADD");
        } else {
            data = null;
        }
        return data;
    }

    public void runNovaSundial() throws XPathExpressionException {
        String data = sourceNovaSundial();
        String novaSundialXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            novaSundialXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            novaSundialXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] novaSundialTokens = data.split("||");
            if (novaSundialTokens.length < 2) {
                return;
            }
            String novaSundialUser = novaSundialTokens[0];
            String novaSundialPass = novaSundialTokens[1];
            XPath novaSundialXPath = XPathFactory.newInstance().newXPath();
            InputSource novaSundialXml = new InputSource(novaSundialXmlFile);
            String novaSundialQuery = "//users/user[name/text()='" + novaSundialUser
                    + "' and pass/text()='" + novaSundialPass + "']" + "/secret/text()";
            String novaSundialSecret = (String) novaSundialXPath.evaluate(novaSundialQuery, novaSundialXml, XPathConstants.STRING);
            System.out.println(novaSundialSecret);
        }
    }
}
