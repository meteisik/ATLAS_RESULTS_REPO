import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P03_V1_GoldenQuartz {

    private void sinkGoldenQuartz(String data) throws XPathExpressionException {
        String goldenQuartzXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            goldenQuartzXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            goldenQuartzXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] goldenQuartzTokens = data.split("||");
            if (goldenQuartzTokens.length < 2) {
                return;
            }
            String goldenQuartzUser = goldenQuartzTokens[0];
            String goldenQuartzPass = goldenQuartzTokens[1];
            XPath goldenQuartzXPath = XPathFactory.newInstance().newXPath();
            InputSource goldenQuartzXml = new InputSource(goldenQuartzXmlFile);
            String goldenQuartzQuery = "//users/user[name/text()='" + goldenQuartzUser
                    + "' and pass/text()='" + goldenQuartzPass + "']" + "/secret/text()";
            String goldenQuartzSecret = (String) goldenQuartzXPath.evaluate(goldenQuartzQuery, goldenQuartzXml, XPathConstants.STRING);
            System.out.println(goldenQuartzSecret);
        }
    }

    public void runGoldenQuartz() throws XPathExpressionException {
        String data;
        data = System.getenv("GOLDEN_QUARTZ_ADD");
        sinkGoldenQuartz(data);
    }
}
