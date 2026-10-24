import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_GoldenAurora {

    public void runGoldenAurora() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("GOLDEN_AURORA_FILTER");
        } else {
            data = null;
        }
        CWE89_P12_V2_GoldenAuroraBase baseObject = new CWE89_P12_V2_GoldenAuroraSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_GoldenAuroraBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_GoldenAuroraSink extends CWE89_P12_V2_GoldenAuroraBase {
    public void action(String data) throws SQLException {
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
