import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P09_V2_SolarQuartzSafe {

    static class Container {
        public String containerOne;
    }

    public void runSolarQuartz() throws XPathExpressionException {
        String data;
        if (true) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE643_P09_V2_SolarQuartzSafeSink()).sinkSolarQuartz(dataContainer);
    }
}

class CWE643_P09_V2_SolarQuartzSafeSink {

    public void sinkSolarQuartz(CWE643_P09_V2_SolarQuartzSafe.Container dataContainer) throws XPathExpressionException {
        String data = dataContainer.containerOne;
        String solarQuartzXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            solarQuartzXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            solarQuartzXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] solarQuartzTokens = data.split("||");
            if (solarQuartzTokens.length < 2) {
                return;
            }
            String solarQuartzUser = solarQuartzTokens[0];
            String solarQuartzPass = solarQuartzTokens[1];
            XPath solarQuartzXPath = XPathFactory.newInstance().newXPath();
            InputSource solarQuartzXml = new InputSource(solarQuartzXmlFile);
            String solarQuartzQuery = "//users/user[name/text()='" + solarQuartzUser
                    + "' and pass/text()='" + solarQuartzPass + "']" + "/secret/text()";
            String solarQuartzSecret = (String) solarQuartzXPath.evaluate(solarQuartzQuery, solarQuartzXml, XPathConstants.STRING);
            System.out.println(solarQuartzSecret);
        }
    }
}
