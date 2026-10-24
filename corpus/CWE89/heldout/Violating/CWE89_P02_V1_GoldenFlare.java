import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V1_GoldenFlare {

    public void runGoldenFlare() throws SQLException {
        String dataCopy;
        {
            String data;
            data = System.getenv("GOLDEN_FLARE_FILTER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
}
