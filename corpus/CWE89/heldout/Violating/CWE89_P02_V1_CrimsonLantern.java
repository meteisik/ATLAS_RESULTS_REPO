import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V1_CrimsonLantern {

    public void runCrimsonLantern() throws SQLException {
        String dataCopy;
        {
            String data;
            data = System.getenv("CRIMSON_LANTERN_FILTER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
}
