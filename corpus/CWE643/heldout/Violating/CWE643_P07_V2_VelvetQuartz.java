import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P07_V2_VelvetQuartz {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void runVelvetQuartz() throws XPathExpressionException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = (new CWE643_P07_V2_VelvetQuartzSource()).sourceVelvetQuartz();
        } else {
            data = null;
        }
        String velvetQuartzXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            velvetQuartzXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            velvetQuartzXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] velvetQuartzTokens = data.split("||");
            if (velvetQuartzTokens.length < 2) {
                return;
            }
            String velvetQuartzUser = velvetQuartzTokens[0];
            String velvetQuartzPass = velvetQuartzTokens[1];
            XPath velvetQuartzXPath = XPathFactory.newInstance().newXPath();
            InputSource velvetQuartzXml = new InputSource(velvetQuartzXmlFile);
            String velvetQuartzQuery = "//users/user[name/text()='" + velvetQuartzUser
                    + "' and pass/text()='" + velvetQuartzPass + "']" + "/secret/text()";
            String velvetQuartzSecret = (String) velvetQuartzXPath.evaluate(velvetQuartzQuery, velvetQuartzXml, XPathConstants.STRING);
            System.out.println(velvetQuartzSecret);
        }
    }
}

class CWE643_P07_V2_VelvetQuartzSource {

    public String sourceVelvetQuartz() {
        String data;
        data = System.getenv("VELVET_QUARTZ_ADD");
        return data;
    }
}
