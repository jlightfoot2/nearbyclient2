package mil.health.sdd.nearbyclient2;

public class FileListItem {
    private String name;
    private boolean isInpsected = false;
    private boolean isValid = false;
    public FileListItem(String name){
        this.name = name;
    }

    public String getName(){
        return name;
    }

    public boolean isValid(){
       return isInpsected() && isValid;
    }

    public boolean isInpsected(){
        return isInpsected;
    }

    public void setInpsected(boolean inspected){
        this.isInpsected = inspected;
    }

    public void setValid(boolean valid){
        this.isValid = valid;
    }
}
