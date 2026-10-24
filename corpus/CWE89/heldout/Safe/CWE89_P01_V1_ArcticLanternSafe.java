import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V1_ArcticLanternSafe {

    public void runArcticLantern() throws SQLException {
        String data;
        data = "foo";
        Connection arcticLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticLantern");
        Statement arcticLanternStatement = null;
        ResultSet arcticLanternRows = null;
        try {
            arcticLanternStatement = arcticLanternConnection.createStatement();
            arcticLanternRows = arcticLanternStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(arcticLanternRows.getRow());
        } finally {
            if (arcticLanternRows != null) {
                arcticLanternRows.close();
            }
            if (arcticLanternStatement != null) {
                arcticLanternStatement.close();
            }
            arcticLanternConnection.close();
        }
    }
}
