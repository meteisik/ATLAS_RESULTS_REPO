import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V1_GoldenSundialSafe {

    private String goldenSundialData;

    private void queryGoldenSundial() throws SQLException {
        String data = goldenSundialData;
        Connection goldenSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenSundial");
        Statement goldenSundialStatement = null;
        ResultSet goldenSundialRows = null;
        try {
            goldenSundialStatement = goldenSundialConnection.createStatement();
            goldenSundialRows = goldenSundialStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(goldenSundialRows.getRow());
        } finally {
            if (goldenSundialRows != null) {
                goldenSundialRows.close();
            }
            if (goldenSundialStatement != null) {
                goldenSundialStatement.close();
            }
            goldenSundialConnection.close();
        }
    }

    public void runGoldenSundial() throws SQLException {
        String data;
        data = "foo";
        goldenSundialData = data;
        queryGoldenSundial();
    }
}
