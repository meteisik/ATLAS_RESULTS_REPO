import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_GoldenFlare {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void runGoldenFlare() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("GOLDEN_FLARE_FILTER");
        } else {
            data = null;
        }
        CWE89_P12_V2_GoldenFlareBase baseObject = new CWE89_P12_V2_GoldenFlareSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_GoldenFlareBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_GoldenFlareSink extends CWE89_P12_V2_GoldenFlareBase {
    public void action(String data) throws SQLException {
        Connection goldenFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenFlare");
        Statement goldenFlareStatement = null;
        ResultSet goldenFlareRows = null;
        try {
            goldenFlareStatement = goldenFlareConnection.createStatement();
            goldenFlareRows = goldenFlareStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(goldenFlareRows.getRow());
        } finally {
            if (goldenFlareRows != null) {
                goldenFlareRows.close();
            }
            if (goldenFlareStatement != null) {
                goldenFlareStatement.close();
            }
            goldenFlareConnection.close();
        }
    }
}
