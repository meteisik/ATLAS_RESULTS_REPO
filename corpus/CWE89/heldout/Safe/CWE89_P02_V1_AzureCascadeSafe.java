import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V1_AzureCascadeSafe {

    public void runAzureCascade() throws SQLException {
        String dataCopy;
        {
            String data;
            data = "foo";
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection azureCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureCascade");
            Statement azureCascadeStatement = null;
            ResultSet azureCascadeRows = null;
            try {
                azureCascadeStatement = azureCascadeConnection.createStatement();
                azureCascadeRows = azureCascadeStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(azureCascadeRows.getRow());
            } finally {
                if (azureCascadeRows != null) {
                    azureCascadeRows.close();
                }
                if (azureCascadeStatement != null) {
                    azureCascadeStatement.close();
                }
                azureCascadeConnection.close();
            }
        }
    }
}
