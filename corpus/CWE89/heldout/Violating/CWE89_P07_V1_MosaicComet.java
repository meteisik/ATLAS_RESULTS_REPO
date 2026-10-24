import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_MosaicComet {

    public void runMosaicComet() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_MosaicCometSource()).loadMosaicComet();
        Connection mosaicCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicComet");
        Statement mosaicCometStatement = null;
        ResultSet mosaicCometRows = null;
        try {
            mosaicCometStatement = mosaicCometConnection.createStatement();
            mosaicCometRows = mosaicCometStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(mosaicCometRows.getRow());
        } finally {
            if (mosaicCometRows != null) {
                mosaicCometRows.close();
            }
            if (mosaicCometStatement != null) {
                mosaicCometStatement.close();
            }
            mosaicCometConnection.close();
        }
    }
}

class CWE89_P07_V1_MosaicCometSource {
    public String loadMosaicComet() {
        String data;
        data = System.getenv("MOSAIC_COMET_FILTER");
        return data;
    }
}
