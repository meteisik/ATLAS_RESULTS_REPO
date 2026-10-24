import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V1_CrimsonHarbor {

    public void runCrimsonHarbor() throws SQLException {
        String dataCopy;
        {
            String data;
            data = System.getenv("CRIMSON_HARBOR_FILTER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection crimsonHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonHarbor");
            Statement crimsonHarborStatement = null;
            ResultSet crimsonHarborRows = null;
            try {
                crimsonHarborStatement = crimsonHarborConnection.createStatement();
                crimsonHarborRows = crimsonHarborStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(crimsonHarborRows.getRow());
            } finally {
                if (crimsonHarborRows != null) {
                    crimsonHarborRows.close();
                }
                if (crimsonHarborStatement != null) {
                    crimsonHarborStatement.close();
                }
                crimsonHarborConnection.close();
            }
        }
    }
}
