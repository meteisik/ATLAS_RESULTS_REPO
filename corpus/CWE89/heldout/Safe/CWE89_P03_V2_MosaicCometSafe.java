import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V2_MosaicCometSafe {

    private void queryMosaicComet(String data) throws SQLException {
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

    public void runMosaicComet() throws SQLException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = "foo";
        }
        queryMosaicComet(data);
    }
}
