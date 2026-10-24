import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_MosaicCometSafe {

    public void runMosaicComet() throws SQLException {
        String data;
        data = "foo";
        (new CWE89_P06_V1_MosaicCometSafeSink()).queryMosaicComet(data);
    }
}

class CWE89_P06_V1_MosaicCometSafeSink {
    public void queryMosaicComet(String data) throws SQLException {
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
