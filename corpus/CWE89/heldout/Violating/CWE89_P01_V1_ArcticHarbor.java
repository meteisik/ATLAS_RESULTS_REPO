import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V1_ArcticHarbor {

    public void runArcticHarbor() throws SQLException {
        String data;
        data = System.getenv("ARCTIC_HARBOR_FILTER");
        Connection arcticHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticHarbor");
        Statement arcticHarborStatement = null;
        ResultSet arcticHarborRows = null;
        try {
            arcticHarborStatement = arcticHarborConnection.createStatement();
            arcticHarborRows = arcticHarborStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(arcticHarborRows.getRow());
        } finally {
            if (arcticHarborRows != null) {
                arcticHarborRows.close();
            }
            if (arcticHarborStatement != null) {
                arcticHarborStatement.close();
            }
            arcticHarborConnection.close();
        }
    }
}
