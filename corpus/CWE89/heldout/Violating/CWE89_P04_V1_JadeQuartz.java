import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V1_JadeQuartz {

    private String loadJadeQuartz() {
        String data;
        data = System.getenv("JADE_QUARTZ_FILTER");
        return data;
    }

    public void runJadeQuartz() throws SQLException {
        String data = loadJadeQuartz();
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
