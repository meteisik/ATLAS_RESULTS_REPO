import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P10_V1_VelvetQuartz {

    public static String data;

    public void runVelvetQuartz() throws XPathExpressionException {
        data = System.getenv("VELVET_QUARTZ_ADD");
        (new CWE643_P10_V1_VelvetQuartzSink()).sinkVelvetQuartz();
    }
}

class CWE643_P10_V1_VelvetQuartzSink {

    public void sinkVelvetQuartz() throws XPathExpressionException {
        String data = CWE643_P10_V1_VelvetQuartz.data;
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
