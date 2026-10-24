import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V2_VelvetQuartzSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    static class Container {
        public String containerOne;
    }

    public void runVelvetQuartz() throws XPathExpressionException {
        String data;
        if (IO.staticTrue) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V2_VelvetQuartzSafeSink()).sinkVelvetQuartz(dataContainer);
    }
}

class CWE643_P09_V2_VelvetQuartzSafeSink {

    public void sinkVelvetQuartz(CWE643_P09_V2_VelvetQuartzSafe.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
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
