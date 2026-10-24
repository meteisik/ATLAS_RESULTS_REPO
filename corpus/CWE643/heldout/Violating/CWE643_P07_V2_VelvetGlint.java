import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P07_V2_VelvetGlint {

    public void runVelvetGlint() throws XPathExpressionException {
        String data;
        if (5 == 5) {
            data = (new CWE643_P07_V2_VelvetGlintSource()).sourceVelvetGlint();
        } else {
            data = null;
        }
        String velvetGlintXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            velvetGlintXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            velvetGlintXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] velvetGlintTokens = data.split("||");
            if (velvetGlintTokens.length < 2) {
                return;
            }
            String velvetGlintUser = velvetGlintTokens[0];
            String velvetGlintPass = velvetGlintTokens[1];
            XPath velvetGlintXPath = XPathFactory.newInstance().newXPath();
            InputSource velvetGlintXml = new InputSource(velvetGlintXmlFile);
            String velvetGlintQuery = "//users/user[name/text()='" + velvetGlintUser
                    + "' and pass/text()='" + velvetGlintPass + "']" + "/secret/text()";
            String velvetGlintSecret = (String) velvetGlintXPath.evaluate(velvetGlintQuery, velvetGlintXml, XPathConstants.STRING);
            System.out.println(velvetGlintSecret);
        }
    }
}

class CWE643_P07_V2_VelvetGlintSource {

    public String sourceVelvetGlint() {
        String data;
        data = System.getenv("VELVET_GLINT_ADD");
        return data;
    }
}
