import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V2_JadeQuartz {
    private static int privateFive = 5;

    public void runJadeQuartz() throws SQLException {
        String dataCopy;
        {
            String data;
            if (privateFive == 5) {
                data = System.getenv("JADE_QUARTZ_FILTER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection jadeQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeQuartz");
            Statement jadeQuartzStatement = null;
            ResultSet jadeQuartzRows = null;
            try {
                jadeQuartzStatement = jadeQuartzConnection.createStatement();
                jadeQuartzRows = jadeQuartzStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(jadeQuartzRows.getRow());
            } finally {
                if (jadeQuartzRows != null) {
                    jadeQuartzRows.close();
                }
                if (jadeQuartzStatement != null) {
                    jadeQuartzStatement.close();
                }
                jadeQuartzConnection.close();
            }
        }
    }
}
