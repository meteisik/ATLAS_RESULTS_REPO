import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V1_GoldenQuartz {

    private String loadGoldenQuartz() {
        String data;
        data = System.getenv("GOLDEN_QUARTZ_FILTER");
        return data;
    }

    public void runGoldenQuartz() throws SQLException {
        String data = loadGoldenQuartz();
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
