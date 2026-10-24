import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P07_V1_NovaCascade {

    public void runNovaCascade() throws XPathExpressionException {
        String data;
        data = (new CWE643_P07_V1_NovaCascadeSource()).sourceNovaCascade();
        String novaCascadeXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            novaCascadeXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            novaCascadeXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] novaCascadeTokens = data.split("||");
            if (novaCascadeTokens.length < 2) {
                return;
            }
            String novaCascadeUser = novaCascadeTokens[0];
            String novaCascadePass = novaCascadeTokens[1];
            XPath novaCascadeXPath = XPathFactory.newInstance().newXPath();
            InputSource novaCascadeXml = new InputSource(novaCascadeXmlFile);
            String novaCascadeQuery = "//users/user[name/text()='" + novaCascadeUser
                    + "' and pass/text()='" + novaCascadePass + "']" + "/secret/text()";
            String novaCascadeSecret = (String) novaCascadeXPath.evaluate(novaCascadeQuery, novaCascadeXml, XPathConstants.STRING);
            System.out.println(novaCascadeSecret);
        }
    }
}

class CWE643_P07_V1_NovaCascadeSource {

    public String sourceNovaCascade() {
        String data;
        data = System.getenv("NOVA_CASCADE_ADD");
        return data;
    }
}
