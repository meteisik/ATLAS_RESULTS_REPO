import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P07_V1_NovaMantis {

    public void runNovaMantis() throws XPathExpressionException {
        String data;
        data = (new CWE643_P07_V1_NovaMantisSource()).sourceNovaMantis();
        String novaMantisXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            novaMantisXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            novaMantisXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] novaMantisTokens = data.split("||");
            if (novaMantisTokens.length < 2) {
                return;
            }
            String novaMantisUser = novaMantisTokens[0];
            String novaMantisPass = novaMantisTokens[1];
            XPath novaMantisXPath = XPathFactory.newInstance().newXPath();
            InputSource novaMantisXml = new InputSource(novaMantisXmlFile);
            String novaMantisQuery = "//users/user[name/text()='" + novaMantisUser
                    + "' and pass/text()='" + novaMantisPass + "']" + "/secret/text()";
            String novaMantisSecret = (String) novaMantisXPath.evaluate(novaMantisQuery, novaMantisXml, XPathConstants.STRING);
            System.out.println(novaMantisSecret);
        }
    }
}

class CWE643_P07_V1_NovaMantisSource {

    public String sourceNovaMantis() {
        String data;
        data = System.getenv("NOVA_MANTIS_ADD");
        return data;
    }
}
