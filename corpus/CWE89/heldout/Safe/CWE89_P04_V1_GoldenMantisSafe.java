import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V1_GoldenMantisSafe {

    private String loadGoldenMantis() {
        String data;
        data = "foo";
        return data;
    }

    public void runGoldenMantis() throws SQLException {
        String data = loadGoldenMantis();
        Connection goldenMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenMantis");
        Statement goldenMantisStatement = null;
        ResultSet goldenMantisRows = null;
        try {
            goldenMantisStatement = goldenMantisConnection.createStatement();
            goldenMantisRows = goldenMantisStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(goldenMantisRows.getRow());
        } finally {
            if (goldenMantisRows != null) {
                goldenMantisRows.close();
            }
            if (goldenMantisStatement != null) {
                goldenMantisStatement.close();
            }
            goldenMantisConnection.close();
        }
    }
}
