import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_MosaicLotus {

    public void runMosaicLotus() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_LOTUS_FILTER");
        (new CWE89_P06_V1_MosaicLotusSink()).queryMosaicLotus(data);
    }
}

class CWE89_P06_V1_MosaicLotusSink {
    public void queryMosaicLotus(String data) throws SQLException {
        Connection mosaicLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicLotus");
        Statement mosaicLotusStatement = null;
        ResultSet mosaicLotusRows = null;
        try {
            mosaicLotusStatement = mosaicLotusConnection.createStatement();
            mosaicLotusRows = mosaicLotusStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(mosaicLotusRows.getRow());
        } finally {
            if (mosaicLotusRows != null) {
                mosaicLotusRows.close();
            }
            if (mosaicLotusStatement != null) {
                mosaicLotusStatement.close();
            }
            mosaicLotusConnection.close();
        }
    }
}
