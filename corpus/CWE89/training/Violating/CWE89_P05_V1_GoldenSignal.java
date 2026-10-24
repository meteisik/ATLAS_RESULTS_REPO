import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V1_GoldenSignal {

    private String goldenSignalData;

    private void queryGoldenSignal() throws SQLException {
        String data = goldenSignalData;
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

    public void runGoldenSignal() throws SQLException {
        String data;
        data = System.getenv("GOLDEN_SIGNAL_FILTER");
        goldenSignalData = data;
        queryGoldenSignal();
    }
}
