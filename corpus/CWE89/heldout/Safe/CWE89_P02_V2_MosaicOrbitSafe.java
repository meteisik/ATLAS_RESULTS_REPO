import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V2_MosaicOrbitSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void runMosaicOrbit() throws SQLException {
        String dataCopy;
        {
            String data;
            if (PRIVATE_STATIC_FINAL_FIVE == 5) {
                data = "foo";
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection mosaicOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicOrbit");
            Statement mosaicOrbitStatement = null;
            ResultSet mosaicOrbitRows = null;
            try {
                mosaicOrbitStatement = mosaicOrbitConnection.createStatement();
                mosaicOrbitRows = mosaicOrbitStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(mosaicOrbitRows.getRow());
            } finally {
                if (mosaicOrbitRows != null) {
                    mosaicOrbitRows.close();
                }
                if (mosaicOrbitStatement != null) {
                    mosaicOrbitStatement.close();
                }
                mosaicOrbitConnection.close();
            }
        }
    }
}
