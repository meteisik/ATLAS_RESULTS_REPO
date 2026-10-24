import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P12_V1_VelvetQuartz {

    public void runVelvetQuartz() throws XPathExpressionException {
        String data;
        data = System.getenv("VELVET_QUARTZ_ADD");
        CWE643_P12_V1_VelvetQuartzBase baseObject = new CWE643_P12_V1_VelvetQuartzSink();
        baseObject.action(data);
    }
}

abstract class CWE643_P12_V1_VelvetQuartzBase {

    public abstract void action(String data) throws XPathExpressionException;
}

class CWE643_P12_V1_VelvetQuartzSink extends CWE643_P12_V1_VelvetQuartzBase {

    public void action(String data) throws XPathExpressionException {
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
