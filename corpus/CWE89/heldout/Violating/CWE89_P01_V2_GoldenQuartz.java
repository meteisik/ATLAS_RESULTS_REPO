import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V2_GoldenQuartz {

    public void runGoldenQuartz() throws SQLException {
        String data;
        while (true) {
            data = System.getenv("GOLDEN_QUARTZ_FILTER");
            break;
        }
        Connection goldenQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenQuartz");
        Statement goldenQuartzStatement = null;
        ResultSet goldenQuartzRows = null;
        try {
            goldenQuartzStatement = goldenQuartzConnection.createStatement();
            goldenQuartzRows = goldenQuartzStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(goldenQuartzRows.getRow());
        } finally {
            if (goldenQuartzRows != null) {
                goldenQuartzRows.close();
            }
            if (goldenQuartzStatement != null) {
                goldenQuartzStatement.close();
            }
            goldenQuartzConnection.close();
        }
    }
}
