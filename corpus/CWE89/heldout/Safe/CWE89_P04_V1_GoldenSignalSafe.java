import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V1_GoldenSignalSafe {

    private String loadGoldenSignal() {
        String data;
        data = "foo";
        return data;
    }

    public void runGoldenSignal() throws SQLException {
        String data = loadGoldenSignal();
        Connection goldenSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenSignal");
        Statement goldenSignalStatement = null;
        ResultSet goldenSignalRows = null;
        try {
            goldenSignalStatement = goldenSignalConnection.createStatement();
            goldenSignalRows = goldenSignalStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(goldenSignalRows.getRow());
        } finally {
            if (goldenSignalRows != null) {
                goldenSignalRows.close();
            }
            if (goldenSignalStatement != null) {
                goldenSignalStatement.close();
            }
            goldenSignalConnection.close();
        }
    }
}
