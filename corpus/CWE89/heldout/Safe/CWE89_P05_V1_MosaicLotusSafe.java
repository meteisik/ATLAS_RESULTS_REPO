import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V1_MosaicLotusSafe {

    private String mosaicLotusData;

    private void queryMosaicLotus() throws SQLException {
        String data = mosaicLotusData;
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

    public void runMosaicLotus() throws SQLException {
        String data;
        data = "foo";
        mosaicLotusData = data;
        queryMosaicLotus();
    }
}
