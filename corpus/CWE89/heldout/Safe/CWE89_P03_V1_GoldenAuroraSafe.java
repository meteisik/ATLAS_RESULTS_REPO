import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V1_GoldenAuroraSafe {

    private void queryGoldenAurora(String data) throws SQLException {
        Connection goldenAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenAurora");
        Statement goldenAuroraStatement = null;
        ResultSet goldenAuroraRows = null;
        try {
            goldenAuroraStatement = goldenAuroraConnection.createStatement();
            goldenAuroraRows = goldenAuroraStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(goldenAuroraRows.getRow());
        } finally {
            if (goldenAuroraRows != null) {
                goldenAuroraRows.close();
            }
            if (goldenAuroraStatement != null) {
                goldenAuroraStatement.close();
            }
            goldenAuroraConnection.close();
        }
    }

    public void runGoldenAurora() throws SQLException {
        String data;
        data = "foo";
        queryGoldenAurora(data);
    }
}
