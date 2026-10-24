import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V2_GoldenAuroraSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void runGoldenAurora() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
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
}
