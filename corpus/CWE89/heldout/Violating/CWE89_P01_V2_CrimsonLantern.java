import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V2_CrimsonLantern {

    public void runCrimsonLantern() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("CRIMSON_LANTERN_FILTER");
        } else {
            data = null;
        }
        Connection crimsonLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonLantern");
        Statement crimsonLanternStatement = null;
        ResultSet crimsonLanternRows = null;
        try {
            crimsonLanternStatement = crimsonLanternConnection.createStatement();
            crimsonLanternRows = crimsonLanternStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(crimsonLanternRows.getRow());
        } finally {
            if (crimsonLanternRows != null) {
                crimsonLanternRows.close();
            }
            if (crimsonLanternStatement != null) {
                crimsonLanternStatement.close();
            }
            crimsonLanternConnection.close();
        }
    }
}
