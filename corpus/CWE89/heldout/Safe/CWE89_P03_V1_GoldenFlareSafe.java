import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V1_GoldenFlareSafe {

    private void queryGoldenFlare(String data) throws SQLException {
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

    public void runGoldenFlare() throws SQLException {
        String data;
        data = "foo";
        queryGoldenFlare(data);
    }
}
