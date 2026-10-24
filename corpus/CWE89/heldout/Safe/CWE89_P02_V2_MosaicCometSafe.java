import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V2_MosaicCometSafe {

    public void runMosaicComet() throws SQLException {
        String dataCopy;
        {
            String data;
            switch (7) {
            case 7:
                data = "foo";
                break;
            default:
                data = null;
                break;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
}
