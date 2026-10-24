import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.xml.sax.InputSource;

public class CWE643_P06_V1_MosaicComet {

    public void runMosaicComet() throws XPathExpressionException {
        String data;
        data = System.getenv("MOSAIC_COMET_ADD");
        (new CWE643_P06_V1_MosaicCometSink()).sinkMosaicComet(data);
    }
}

class CWE643_P06_V1_MosaicCometSink {

    public void sinkMosaicComet(String data) throws XPathExpressionException {
        String mosaicCometXmlFile = null;
        if (System.getProperty("os.name").toLowerCase().indexOf("win") >= 0) {
            mosaicCometXmlFile = "\\src\\testcases\\CWE643_Xpath Injection\\CWE643_Xpath_Injection__Helper.xml";
        } else {
            mosaicCometXmlFile = "./src/testcases/CWE643_Xpath Injection/CWE643_Xpath_Injection__Helper.xml";
        }
        if (data != null) {
            String[] mosaicCometTokens = data.split("||");
            if (mosaicCometTokens.length < 2) {
                return;
            }
            String mosaicCometUser = mosaicCometTokens[0];
            String mosaicCometPass = mosaicCometTokens[1];
            XPath mosaicCometXPath = XPathFactory.newInstance().newXPath();
            InputSource mosaicCometXml = new InputSource(mosaicCometXmlFile);
            String mosaicCometQuery = "//users/user[name/text()='" + mosaicCometUser
                    + "' and pass/text()='" + mosaicCometPass + "']" + "/secret/text()";
            String mosaicCometSecret = (String) mosaicCometXPath.evaluate(mosaicCometQuery, mosaicCometXml, XPathConstants.STRING);
            System.out.println(mosaicCometSecret);
        }
    }
}
