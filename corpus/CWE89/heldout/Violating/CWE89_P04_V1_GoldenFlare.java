import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V1_GoldenFlare {

    private String loadGoldenFlare() {
        String data;
        data = System.getenv("GOLDEN_FLARE_FILTER");
        return data;
    }

    public void runGoldenFlare() throws SQLException {
        String data = loadGoldenFlare();
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
